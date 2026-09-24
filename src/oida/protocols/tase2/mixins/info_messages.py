"""
TASE.2 Information Messages Mixin

Handles Block 4 Information Message operations:
- IM store discovery and listing
- Message listing and reading
- IM transfer attributes
- Message writing and deletion
- IM store creation
- IM security analysis
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class InfoMessagesMixin(_ScannerBase):
    """Mixin providing TASE.2 Information Message (Block 4) operations."""

    def _discover_information_messages(self, connection: Any, results: Dict[str, Any]) -> None:
        """
        Discover Information Message stores across all domains.

        Checks each discovered domain for IM stores and populates results.

        Args:
            connection: Active TASE.2 connection
            results: Results dict to populate
        """
        if not results.get("domains"):
            return

        im_stores = []

        for domain in results["domains"]:
            domain_name = domain.get("name", domain) if isinstance(domain, dict) else domain
            stores = self.get_information_message_stores(connection, domain_name)
            if stores:
                im_stores.extend(stores)
                self.logger.display(f"Found {len(stores)} IM store(s) in domain {domain_name}")

        if im_stores:
            results["im_stores"] = im_stores
            results.setdefault("conformance_blocks", []).append("Block 4 (Information Messages)")

    def get_information_message_stores(self, connection: Any, domain: str) -> List[Dict[str, Any]]:
        """
        List all Information Message stores in a domain.

        Per IEC 60870-6-503, IM Transfer Sets include:
        - info_reference: Information Reference for bilateral table access control
        - local_reference: Local Reference for client-side identification
        - scope: VCC (server-wide) or ICC (bilateral-specific)

        Uses get_info_buffers() (pyiec61850-ng >= 1.6.0.9) for structured
        buffer info.

        Args:
            connection: Active TASE.2 connection
            domain: Domain name to query

        Returns:
            List of IM store info dicts with name, info_reference, local_reference,
            scope, max_messages, current_count, storage_status
        """
        from oida.protocols.tase2.scanner import TASE2IMScope, TASE2IMStorageStatus

        stores = []

        try:
            buffers = connection.get_info_buffers(domain)
            scope = TASE2IMScope.VCC if domain.upper().startswith("VCC") else TASE2IMScope.ICC

            for buf in buffers:
                # InformationBuffer exposes name/domain/max_size/entry_count/messages.
                # Derive storage_status from capacity since the library has no such
                # field; FULL when at capacity, otherwise AVAILABLE for writes.
                if buf.max_size and buf.entry_count >= buf.max_size:
                    storage_status = TASE2IMStorageStatus.FULL
                else:
                    storage_status = TASE2IMStorageStatus.AVAILABLE

                # Key names must match the consumers (_analyze_im_security /
                # nxc list_im_stores), which read max_messages / current_count
                # / storage_status.
                stores.append(
                    {
                        "domain": domain,
                        "name": buf.name,
                        "max_messages": buf.max_size,
                        "current_count": buf.entry_count,
                        "storage_status": storage_status,
                        "scope": scope,
                    }
                )

        except Exception as e:
            self.logger.debug(f"Error getting IM stores from {domain}: {e}")

        return stores

    def _get_store_messages(self, connection: Any, domain: str, store: str) -> List[Any]:
        """
        Return the raw message objects owned by a single IM store.

        connection.get_info_messages(domain) is domain-wide and does not scope
        by store, so resolve the owning InformationBuffer (by name) and read its
        per-store .messages list. Falls back to an empty list when the store is
        not present in the domain.

        Args:
            connection: Active TASE.2 connection
            domain: Domain name
            store: IM store name

        Returns:
            List of raw message objects belonging to ``store``
        """
        buffers = connection.get_info_buffers(domain)
        for buf in buffers:
            if buf.name == store:
                return list(getattr(buf, "messages", []) or [])
        return []

    def get_information_messages(
        self, connection: Any, domain: str, store: str
    ) -> List[Dict[str, Any]]:
        """
        List messages in an Information Message store.

        Per IEC 60870-6-503, each message includes:
        - info_reference: Information Reference (inherited from store)
        - local_reference: Local Reference for this message

        Scopes to the named IM store by reading the owning InformationBuffer's
        per-store message list (get_info_buffers), since
        connection.get_info_messages(domain) is domain-wide and returns the same
        unfiltered list for every store in the domain.

        Args:
            connection: Active TASE.2 connection
            domain: Domain name
            store: IM store name

        Returns:
            List of message info dicts with message_id, info_ref, local_ref,
            size, time_created
        """
        messages = []

        try:
            for msg in self._get_store_messages(connection, domain, store):
                messages.append(
                    {
                        "message_id": str(msg.msg_id),
                        "info_ref": msg.info_ref,
                        "local_ref": msg.local_ref,
                        "size": msg.size,
                        "time_created": msg.timestamp.isoformat() if msg.timestamp else None,
                    }
                )

        except Exception as e:
            self.logger.debug(f"Error listing messages in {domain}/{store}: {e}")

        return messages

    def read_information_message(
        self, connection: Any, domain: str, store: str, message_id: str
    ) -> Dict[str, Any]:
        """
        Read full content of an Information Message.

        Per IEC 60870-6-503, message includes info_reference and local_reference
        for bilateral table access control.

        Uses get_info_message_by_ref() (pyiec61850-ng >= 1.6.0.9).

        Args:
            connection: Active TASE.2 connection
            domain: Domain name
            store: IM store name
            message_id: Message ID to read (the msg_id emitted by
                get_information_messages / --list-messages)

        Returns:
            Dict with message content, info_ref, local_ref, time_created, and any error
        """
        result = {
            "domain": domain,
            "store": store,
            "message_id": message_id,
            "info_ref": 0,
            "local_ref": 0,
            "content": None,
            "time_created": None,
            "error": None,
        }

        try:
            # list-messages emits msg_id as the identifier, but the library
            # only looks messages up by info_ref. Resolve the user-supplied
            # msg_id to its info_ref via the store's own message listing so the
            # id shown to the operator is the id this method accepts, and so a
            # msg_id belonging to a different store in the same domain is not
            # resolved as if it lived in the requested store.
            info_ref = None
            for listed in self._get_store_messages(connection, domain, store):
                if str(listed.msg_id) == str(message_id):
                    info_ref = listed.info_ref
                    break

            if info_ref is None:
                result["error"] = f"Message {message_id} not found in {domain}/{store}"
                self.logger.debug(result["error"])
                return result

            msg = connection.get_info_message_by_ref(domain, info_ref)
            if msg is not None:
                result["content"] = msg.text
                result["info_ref"] = msg.info_ref
                result["local_ref"] = msg.local_ref
                result["message_id"] = str(msg.msg_id)
                result["time_created"] = msg.timestamp.isoformat() if msg.timestamp else None
                self.logger.display(f"Read message {message_id} from {domain}/{store}")
        except Exception as e:
            result["error"] = str(e)
            self.logger.debug(f"Error reading message {domain}/{store}/{message_id}: {e}")

        return result

    def write_information_message(
        self,
        connection: Any,
        domain: str,
        store: str,
        content: str,
        priority: int = 5,
        info_reference: str = "",
        local_reference: str = "",
    ) -> Dict[str, Any]:
        """
        Write/append a message to an Information Message store.

        Per IEC 60870-6-503, the message is sent with info_reference and
        local_reference for bilateral table access control.

        Args:
            connection: Active TASE.2 connection
            domain: Domain name
            store: IM store name
            content: Message content (text or base64 for binary)
            priority: Message priority 1-9 (1=highest)
            info_reference: Information Reference (defaults to store name)
            local_reference: Local Reference for client identification

        Returns:
            Dict with success, message_id, info_reference, local_reference, and any error
        """
        info_ref_int = int(info_reference) if info_reference and info_reference.isdigit() else 0
        local_ref_int = int(local_reference) if local_reference and local_reference.isdigit() else 0
        result = {
            "domain": domain,
            "store": store,
            "info_ref": info_ref_int,
            "local_ref": local_ref_int,
            "success": False,
            "message_id": None,
            "error": None,
        }

        if self.read_only:
            result["error"] = "Read-only mode - cannot write messages"
            self.logger.warning("Cannot write IM in read-only mode")
            return result

        try:
            content_bytes = content.encode("utf-8") if isinstance(content, str) else content
            # Use a real, unique message id per write. Previously this sent
            # int(priority) as msg_id, so every message got the same id (5),
            # colliding on read/delete round-trips. Priority is not a parameter
            # of the library's send_info_message(), so it is not passed here.
            self._next_im_msg_id = getattr(self, "_next_im_msg_id", 0) + 1
            msg_id_int = self._next_im_msg_id
            success = connection.send_info_message(
                domain,
                info_ref=info_ref_int,
                local_ref=local_ref_int,
                msg_id=msg_id_int,
                content=content_bytes,
            )
            if success:
                result["success"] = True
                result["message_id"] = str(msg_id_int)
                self.logger.display(f"Sent info message to {domain}/{store}")

        except Exception as e:
            result["error"] = str(e)
            self.logger.fail(f"Failed to write message to {domain}/{store}: {e}")

        return result

    def delete_information_message(
        self, connection: Any, domain: str, store: str, message_id: str
    ) -> Dict[str, Any]:
        """
        Delete a message from an Information Message store.

        Args:
            connection: Active TASE.2 connection
            domain: Domain name
            store: IM store name
            message_id: Message ID to delete

        Returns:
            Dict with success and any error
        """
        result = {
            "domain": domain,
            "store": store,
            "message_id": message_id,
            "success": False,
            "error": None,
        }

        if self.read_only:
            result["error"] = "Read-only mode - cannot delete messages"
            self.logger.warning("Cannot delete IM in read-only mode")
            return result

        # pyiec61850-ng does not expose IM message deletion
        result["error"] = "IM message deletion not supported by pyiec61850-ng"
        self.logger.debug(f"IM delete not available for {domain}/{store}/{message_id}")

        return result

    def _analyze_im_security(self, results: Dict[str, Any], features: Dict[str, bool]) -> List[str]:
        """
        Analyze Information Messages security posture.

        Args:
            results: Scan results containing im_stores
            features: Supported features dict

        Returns:
            List of security concerns
        """
        from oida.protocols.tase2.scanner import TASE2IMStorageStatus

        concerns = []

        if not features.get("block4"):
            return concerns

        concerns.append("Block 4 (Information Messages) enabled - text/file transfer possible")

        im_stores = results.get("im_stores", [])

        if im_stores:
            total_capacity = sum(s.get("max_messages", 0) for s in im_stores)
            total_messages = sum(s.get("current_count", 0) for s in im_stores)

            concerns.append(f"Found {len(im_stores)} IM store(s) with {total_messages} messages")

            if total_capacity > 500:
                concerns.append(
                    f"Large IM capacity ({total_capacity} msgs) - data exfiltration potential"
                )

            # Check for write access concerns
            for store in im_stores:
                status = store.get("storage_status", "")
                if status == TASE2IMStorageStatus.AVAILABLE:
                    concerns.append(
                        f"IM store {store['name']} accepting writes - message injection risk"
                    )
                    break

        return concerns
