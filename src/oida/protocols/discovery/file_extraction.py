"""
File extraction from PCAP using tshark --export-objects.

Wraps tshark's built-in reassembly for HTTP, SMB, FTP-data, TFTP, DICOM, and IMF.
"""

import os
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional

from oida.utils.common_types import safe_output_path
from oida.utils.ics_logger import get_module_logger

logger = get_module_logger(__name__)

EXPORT_PROTOCOLS = {"http", "smb", "ftp-data", "tftp", "dicom", "imf"}


class FileExtractor:
    """Extract files from PCAP via tshark --export-objects."""

    def __init__(
        self,
        pcap_file: str,
        output_dir: Optional[str] = None,
        protocols: Optional[List[str]] = None,
    ):
        self.pcap_file = pcap_file
        self.protocols = [p for p in (protocols or EXPORT_PROTOCOLS) if p in EXPORT_PROTOCOLS]
        self._files: List[Dict[str, Any]] = []
        self._tshark = shutil.which("tshark")

        if output_dir:
            self.output_dir = output_dir
        else:
            base = os.path.splitext(os.path.basename(pcap_file))[0]
            self.output_dir = os.path.join(os.path.dirname(pcap_file) or ".", f"{base}_extracted")

        if not self._tshark:
            raise RuntimeError("tshark not found - install Wireshark/tshark")

    def extract_all(self) -> List[Dict[str, Any]]:
        """Run extraction for each protocol, return list of extracted file dicts."""
        os.makedirs(self.output_dir, exist_ok=True)

        for proto in self.protocols:
            self._extract_protocol(proto)

        logger.debug("extract_all: %d files extracted to %s", len(self._files), self.output_dir)
        return self._files

    def _extract_protocol(self, proto: str) -> None:
        """Run tshark --export-objects for one protocol."""
        tmpdir = tempfile.mkdtemp(prefix=f"oida_{proto}_")
        try:
            cmd = [
                self._tshark,
                "-r",
                self.pcap_file,
                "--export-objects",
                f"{proto},{tmpdir}",
                "-Q",
            ]
            logger.debug("_extract_protocol: %s", " ".join(cmd))
            result = subprocess.run(cmd, capture_output=True, timeout=120)
            if result.returncode != 0:
                stderr = result.stderr.decode(errors="replace").strip()
                logger.debug("tshark export-objects %s failed: %s", proto, stderr)
                return

            proto_dir = os.path.join(self.output_dir, proto)
            for fname in os.listdir(tmpdir):
                src = os.path.join(tmpdir, fname)
                if not os.path.isfile(src):
                    continue
                size = os.path.getsize(src)
                if size == 0:
                    continue

                os.makedirs(proto_dir, exist_ok=True)
                # Sanitise filename: tshark filenames originate from network
                # data and may contain path-traversal sequences.
                try:
                    dst = safe_output_path(fname, proto_dir)
                except ValueError:
                    logger.debug("Skipping unsafe filename from tshark: %s", fname)
                    continue
                # Avoid collisions
                if os.path.exists(dst):
                    safe_base = os.path.basename(dst)
                    base, ext = os.path.splitext(safe_base)
                    i = 1
                    while os.path.exists(dst):
                        dst = safe_output_path(f"{base}_{i}{ext}", proto_dir)
                        i += 1
                shutil.move(src, dst)

                self._files.append(
                    {
                        "protocol": proto,
                        "filename": os.path.basename(dst),
                        "size": size,
                        "path": dst,
                    }
                )
        except subprocess.TimeoutExpired:
            logger.debug("tshark export-objects %s timed out", proto)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def get_files_summary(self) -> List[Dict[str, Any]]:
        return list(self._files)

    def get_statistics(self) -> Dict[str, Any]:
        by_proto: Dict[str, Dict[str, int]] = {}
        for f in self._files:
            p = f["protocol"]
            if p not in by_proto:
                by_proto[p] = {"count": 0, "bytes": 0}
            by_proto[p]["count"] += 1
            by_proto[p]["bytes"] += f["size"]
        return {
            "total_files": len(self._files),
            "total_bytes": sum(f["size"] for f in self._files),
            "by_protocol": by_proto,
        }
