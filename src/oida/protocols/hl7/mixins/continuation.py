"""
HL7 Continuation Mixin

Handles continuation/fragmentation:
- DSC segment handling
- MSH-14 continuation pointer
- Fragment reassembly
- Driving the continuation loop on the query path
"""

from typing import List, Optional

from hl7apy.core import Message, Segment
from hl7apy.parser import parse_message

from ..segments import HL7SegmentParser
from ._helpers import populate_msh

# Hard cap on continuation rounds so a misbehaving/hostile server that keeps
# returning a DSC pointer can't drive an unbounded request loop.
MAX_CONTINUATION_ROUNDS = 64


class ContinuationMixin:
    """Mixin providing HL7 continuation/fragmentation building blocks.

    Exposes the DSC/MSH-14 detection (_check_continuation), QCN request
    builder (_create_continuation_request), and fragment reassembly
    (_reassemble_fragments) helpers, plus _send_query_message which chains
    them into the live query path so paginated (DSC/MSH-14) results are
    followed and reassembled instead of being silently truncated.
    """

    def _send_query_message(self, message: str) -> Optional[bytes]:
        """Send a query and follow DSC/MSH-14 continuation pointers.

        Sends the initial query frame via _send_mllp_message (byte-identical
        to a plain single-shot send). If the response carries a continuation
        pointer, repeatedly issues QCN^J01 continuation requests over the same
        connection, collecting every returned frame, then reassembles them
        into a single payload.

        When there is NO continuation pointer (the common case) this returns
        the single frame unchanged with no extra requests issued.
        """
        first = self._send_mllp_message(message)
        if not first:
            return first

        pointer, _style = self._check_continuation(first)
        if not pointer:
            # No continuation: behave exactly like a single-shot send.
            return first

        fragments: List[bytes] = [first]
        rounds = 0
        while pointer and rounds < MAX_CONTINUATION_ROUNDS:
            rounds += 1
            cont_request = self._create_continuation_request(pointer)
            if not cont_request:
                break

            self.logger.debug(f"Following HL7 continuation pointer (round {rounds})")
            next_frame = self._send_mllp_message(cont_request)
            if not next_frame:
                break

            fragments.append(next_frame)
            pointer, _style = self._check_continuation(next_frame)

        if pointer and rounds >= MAX_CONTINUATION_ROUNDS:
            self.logger.warning(
                "HL7 continuation exceeded %d rounds; truncating result",
                MAX_CONTINUATION_ROUNDS,
            )

        if len(fragments) > 1:
            self.logger.display(f"Reassembled {len(fragments)} HL7 continuation fragments")

        return self._reassemble_fragments(fragments)

    def _check_continuation(self, response: bytes) -> tuple:
        """Check if response has continuation (DSC segment or MSH-14)"""
        try:
            msg_str = response.decode("utf-8", errors="ignore")

            # Check DSC segment
            for segment in msg_str.split("\r"):
                if segment.startswith("DSC|"):
                    dsc = HL7SegmentParser.parse_dsc(segment)
                    pointer = dsc.get("ContinuationPointer", "")
                    style = dsc.get("ContinuationStyle", "I")  # I=Interactive
                    if pointer:
                        return (pointer, style)

            # Check MSH-14 (Continuation Pointer)
            msg = parse_message(msg_str)
            if hasattr(msg, "msh"):
                pointer = self._get_field_value(msg.msh, "msh_14")
                if pointer:
                    return (pointer, "I")

            return (None, None)

        except Exception as e:
            self.logger.debug(f"Continuation check failed: {e}")
            return (None, None)

    def _create_continuation_request(self, continuation_pointer: str) -> Optional[str]:
        """Create QCN (Cancel Query/Continue Response) for continuation"""
        try:
            version = self._get_version()
            msg = Message("QCN_J01", version=version)

            populate_msh(
                msg,
                self.args,
                version=version,
                msg_type="QCN^J01",
                control_prefix="CNT",
            )
            msg.msh.msh_14 = continuation_pointer  # Continuation pointer

            # QID segment (Query Identification)
            qid = Segment("QID", version=version)
            qid.qid_1 = continuation_pointer
            qid.qid_2 = "CN"  # Continue query
            msg.add(qid)

            return msg.to_er7()

        except Exception as e:
            self.logger.debug(f"Failed to create continuation request: {e}")
            return None

    def _reassemble_fragments(self, fragments: List[bytes]) -> bytes:
        """Reassemble fragmented HL7 messages"""
        if not fragments:
            return b""

        if len(fragments) == 1:
            return fragments[0]

        # For HL7, typically keep MSH/MSA from first fragment,
        # and append data segments from subsequent fragments
        result_segments = []
        header_added = False

        for fragment in fragments:
            segments = HL7SegmentParser.split_message(fragment)
            for segment in segments:
                # Keep MSH, MSA, QAK from first fragment only
                if segment.startswith(("MSH|", "MSA|", "QAK|")):
                    if not header_added:
                        result_segments.append(segment)
                # Skip DSC segments (continuation markers)
                elif segment.startswith("DSC|"):
                    continue
                else:
                    result_segments.append(segment)

            header_added = True

        return "\r".join(result_segments).encode("utf-8")
