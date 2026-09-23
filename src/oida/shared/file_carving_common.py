"""File carving shared data structures and logic.

Provides:
- ExtractedFile / StreamBuffer dataclasses
- FileCarvingMixin with the carving algorithm, file recording, device tracking,
  save/summary/statistics methods

Each consumer defines its own FILE_SIGNATURES dict and packet processing.
"""

import hashlib
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Tuple


@dataclass
class ExtractedFile:
    """Extracted file from network traffic."""

    file_type: str  # "JPEG", "PNG", "GIF", "PDF", "ZIP", etc.
    extension: str  # ".jpg", ".png", etc.
    size: int  # File size in bytes
    md5_hash: str  # MD5 hash of file content
    source_ip: str
    dest_ip: str
    source_mac: str
    dest_mac: str
    protocol: str  # "TCP" or "UDP"
    timestamp: str
    data: bytes = field(repr=False)  # Actual file data
    # True only when the bytes actually landed in output_dir (see _save_file).
    saved: bool = False


@dataclass
class StreamBuffer:
    """Buffer for tracking TCP/UDP stream data."""

    src_ip: str
    dst_ip: str
    protocol: str
    src_mac: str = ""
    dst_mac: str = ""
    data: bytearray = field(default_factory=bytearray)
    extracted_offsets: List[Tuple[int, int]] = field(default_factory=list)
    bytes_since_last_carve: int = 0  # Track bytes since last carve attempt
    capped: bool = False  # True when buffer hit max size


class FileCarvingMixin:
    """Shared carving algorithm, recording, device tracking, and summary methods.

    Subclasses must set:
        self.files: List[ExtractedFile]
        self.output_dir: Optional[str]
        self.FILE_SIGNATURES: Dict  (class or instance attribute)

    And provide:
        self.logger            -- logging interface
        self._lock             -- threading lock for discovered_devices
        self.discovered_devices -- dict of discovered devices
        self._get_logger()     -- optional, defaults to self.logger
    """

    # Subclasses override with their own signatures
    FILE_SIGNATURES: Dict[str, Any] = {}

    # ---- carving algorithm ----

    def _try_extract_files(self, stream: StreamBuffer, force: bool = False) -> None:
        """Try to extract files from stream data using header-footer carving."""
        data = bytes(stream.data)

        for file_type, sig_info in self.FILE_SIGNATURES.items():
            headers = sig_info["headers"]
            footers = sig_info["footers"]
            extension = sig_info["extension"]
            max_size = sig_info["max_size"]
            min_size = sig_info.get("min_size", 100)

            for header in headers:
                pos = 0
                while pos < len(data):
                    header_pos = data.find(header, pos)
                    if header_pos == -1:
                        break

                    if self._already_extracted(stream, header_pos):
                        pos = header_pos + len(header)
                        continue

                    for footer in footers:
                        footer_pos = data.find(footer, header_pos + len(header))
                        if footer_pos == -1:
                            continue

                        end_pos = footer_pos + len(footer)
                        if file_type == "ZIP":
                            # The EOCD signature (504B0506) is only the first
                            # 4 of the record's >=22 fixed bytes; ending the
                            # carve right after the signature drops the
                            # disk/central-directory count/size/offset
                            # fields and the trailing comment, producing a
                            # truncated/invalid archive. The comment length
                            # is a little-endian uint16 at the last 2 of
                            # those 22 fixed bytes -- read it so the carve
                            # includes any archive comment too.
                            eocd_fixed_end = footer_pos + 22
                            if eocd_fixed_end > len(data):
                                if not force:
                                    # Fixed EOCD record not fully buffered
                                    # yet; retry once more stream data
                                    # arrives instead of carving a
                                    # truncated file now.
                                    continue
                                eocd_fixed_end = len(data)
                                comment_len = 0
                            else:
                                comment_len = int.from_bytes(
                                    data[footer_pos + 20 : eocd_fixed_end], "little"
                                )
                            end_pos = min(eocd_fixed_end + comment_len, len(data))

                        file_size = end_pos - header_pos

                        if file_size > max_size or file_size < min_size:
                            pos = header_pos + len(header)
                            continue

                        file_data = data[header_pos:end_pos]
                        self._record_file(stream, file_type, extension, file_data)
                        stream.extracted_offsets.append((header_pos, end_pos))
                        break

                    pos = header_pos + len(header)

    @staticmethod
    def _already_extracted(stream: StreamBuffer, offset: int) -> bool:
        """Check if we already extracted a file from this offset."""
        for start, end in stream.extracted_offsets:
            if start <= offset < end:
                return True
        return False

    # ---- recording ----

    def _record_file(
        self,
        stream: StreamBuffer,
        file_type: str,
        extension: str,
        data: bytes,
    ) -> None:
        """Record extracted file."""
        md5_hash = hashlib.md5(data, usedforsecurity=False).hexdigest()  # nosec B324

        for f in self.files:
            if f.md5_hash == md5_hash:
                return

        extracted = ExtractedFile(
            file_type=file_type,
            extension=extension,
            size=len(data),
            md5_hash=md5_hash,
            source_ip=stream.src_ip,
            dest_ip=stream.dst_ip,
            source_mac=stream.src_mac,
            dest_mac=stream.dst_mac,
            protocol=stream.protocol,
            timestamp=datetime.now().isoformat(),
            data=data,
        )
        self.files.append(extracted)

        self.logger.info(
            f"File carved: {file_type} ({len(data)} bytes) {stream.src_ip} -> {stream.dst_ip}"
        )

        self._update_devices(extracted)

        if self.output_dir:
            extracted.saved = self._save_file(extracted)

    def _save_file(self, extracted: ExtractedFile) -> bool:
        """Save extracted file to disk. Override for safe_output_path variant.

        Returns True when the file actually landed on disk. Callers use the
        return value to report honestly: a carve that cannot be saved must not
        be logged as an extraction.
        """
        if not self.output_dir:
            return False
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            filename = f"{extracted.md5_hash}{extracted.extension}"
            filepath = os.path.join(self.output_dir, filename)
            with open(filepath, "wb") as f:
                f.write(extracted.data)
            self.logger.debug(f"Saved: {filepath}")
            return True
        except Exception as e:
            # Visible, not debug: previously this was swallowed at debug level,
            # so the operator saw "File carved" and a files summary entry while
            # nothing had been written.
            self.logger.error(f"Failed to save carved file to {self.output_dir}: {e}")
            return False

    # ---- device tracking ----

    def _update_devices(self, extracted: ExtractedFile) -> None:
        """Update device entries with file transfer information."""
        from oida.protocols.discovery.core import DiscoveredDevice, is_valid_discovered_ip

        file_info = {
            "file_type": extracted.file_type,
            "extension": extracted.extension,
            "size": extracted.size,
            "md5": extracted.md5_hash,
            "timestamp": extracted.timestamp,
        }

        with self._lock:
            # Sender device
            if is_valid_discovered_ip(extracted.source_ip):
                sender_key = (
                    extracted.source_mac
                    if extracted.source_mac
                    else f"file-sender:{extracted.source_ip}"
                )
                if sender_key not in self.discovered_devices:
                    device = DiscoveredDevice(
                        mac_address=extracted.source_mac,
                        ip_addresses=[extracted.source_ip],
                        name=f"File Sender ({extracted.source_ip})",
                        manufacturer="",
                        model="",
                        device_type="File Server",
                        discovered_by=["file-carving"],
                        first_seen=datetime.now().isoformat(),
                        last_seen=datetime.now().isoformat(),
                    )
                    device.file_carving_data = {
                        "role": "sender",
                        "files_sent": [file_info],
                        "protocol": extracted.protocol,
                    }
                    self.discovered_devices[sender_key] = device
                else:
                    device = self.discovered_devices[sender_key]
                    device.last_seen = datetime.now().isoformat()
                    if device.file_carving_data:
                        device.file_carving_data.setdefault("files_sent", []).append(file_info)

            # Receiver device
            if is_valid_discovered_ip(extracted.dest_ip):
                receiver_key = (
                    extracted.dest_mac
                    if extracted.dest_mac
                    else f"file-receiver:{extracted.dest_ip}"
                )
                if receiver_key not in self.discovered_devices:
                    device = DiscoveredDevice(
                        mac_address=extracted.dest_mac,
                        ip_addresses=[extracted.dest_ip],
                        name=f"File Receiver ({extracted.dest_ip})",
                        manufacturer="",
                        model="",
                        device_type="Client",
                        discovered_by=["file-carving"],
                        first_seen=datetime.now().isoformat(),
                        last_seen=datetime.now().isoformat(),
                    )
                    device.file_carving_data = {
                        "role": "receiver",
                        "files_received": [file_info],
                        "protocol": extracted.protocol,
                    }
                    self.discovered_devices[receiver_key] = device
                else:
                    device = self.discovered_devices[receiver_key]
                    device.last_seen = datetime.now().isoformat()
                    if device.file_carving_data:
                        device.file_carving_data.setdefault("files_received", []).append(file_info)

    # ---- public helpers ----

    def get_files_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all extracted files (without data).

        ``saved`` reflects whether the bytes actually reached output_dir —
        False means the file exists only in memory (e.g. the output directory
        was unwritable).
        """
        return [
            {
                "file_type": f.file_type,
                "extension": f.extension,
                "size": f.size,
                "md5": f.md5_hash,
                "source_ip": f.source_ip,
                "dest_ip": f.dest_ip,
                "protocol": f.protocol,
                "timestamp": f.timestamp,
                "saved": f.saved,
            }
            for f in self.files
        ]

    def get_statistics(self) -> Dict[str, Any]:
        """Get file extraction statistics."""
        stats: Dict[str, Any] = {
            "total_files": len(self.files),
            "total_bytes": sum(f.size for f in self.files),
            "by_type": {},
        }

        for f in self.files:
            if f.file_type not in stats["by_type"]:
                stats["by_type"][f.file_type] = {"count": 0, "bytes": 0}
            stats["by_type"][f.file_type]["count"] += 1
            stats["by_type"][f.file_type]["bytes"] += f.size

        return stats
