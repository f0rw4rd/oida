"""ETS project file parsing and password cracking.

Provides utilities for handling KNX ETS project files (.knxproj),
including password cracking, hash extraction, and project parsing.
"""

import io
import os
import shutil
import subprocess
import tempfile
from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import Manager
from pathlib import Path
from typing import Dict, Any, Optional
from zipfile import ZipFile

from oida.protocols.knx.helpers import _get_xknxproject, _get_xknxproject_exceptions, _get_pyzipper
from oida.utils import ics_logger as module
from oida.utils.ics_logger import get_module_logger

logger = get_module_logger(__name__)


# ============================================================================
# Module-level functions for multiprocessing
# ============================================================================


def _test_knxproj_password_mp(args: tuple) -> Optional[str]:
    """Test password for knxproj file (multiprocessing-compatible).

    Args:
        args: Tuple of (file_path, password, stop_flag_value)

    Returns:
        Password if valid, None otherwise
    """
    file_path, password, stop_flag = args
    if stop_flag.value:
        return None

    try:
        XKNXProj = _get_xknxproject()
        if XKNXProj is None:
            return None
        proj = XKNXProj(Path(file_path), password=password)
        proj.parse()
        return password
    except Exception as e:
        logger.debug(f"Failed to get XKNXProj: {e}")
        return None


def _test_knxproj_password_fast_mp(args: tuple) -> Optional[str]:
    """Fast password test (multiprocessing-compatible).

    Only tests ZIP decryption, skips XML parsing for speed.

    Args:
        args: Tuple of (file_path, password, stop_flag, ets_version, project_id)

    Returns:
        Password if valid, None otherwise
    """
    file_path, password, stop_flag, ets_version, project_id = args
    if stop_flag.value:
        return None

    pyzipper = _get_pyzipper()
    if pyzipper is None:
        # Fallback to full test if pyzipper not available
        return _test_knxproj_password_mp((file_path, password, stop_flag))

    inner_zip_name = project_id + ".zip"

    try:
        # Read inner ZIP from outer archive
        with ZipFile(file_path) as outer:
            inner_data = outer.read(inner_zip_name)

        # For ETS6: Derive key using PBKDF2 (shared helper)
        if ets_version == "ETS6":
            zip_password = derive_ets6_zip_password(password).encode("ascii")
        else:
            # ETS5: Direct password
            zip_password = password.encode()

        # Try to open inner ZIP with derived password
        with pyzipper.AESZipFile(io.BytesIO(inner_data)) as inner:
            inner.setpassword(zip_password)
            # Read first file to verify password (namelist() doesn't validate!)
            files = inner.namelist()
            if files:
                inner.read(files[0])  # Actually decrypt to verify password
        return password

    except Exception as e:
        logger.debug(f"Operation failed: {e}")
        return None


# ============================================================================
# ETS Project Info and Parsing
# ============================================================================


def get_knxproj_info(file_path: str) -> Dict[str, Any]:
    """Get .knxproj file info without full parsing.

    Detects project ID, ETS version, and whether the file is password protected.

    Args:
        file_path: Path to .knxproj file

    Returns:
        Dict with keys: file, password_protected, ets_version, project_id
    """
    logger.debug(f"Getting knxproj info: {file_path}")
    info = {
        "file": file_path,
        "password_protected": False,
        "ets_version": "unknown",
        "project_id": None,
    }

    try:
        with ZipFile(file_path, mode="r") as zf:
            # Find project ID from signature file
            for entry in zf.infolist():
                if entry.filename.startswith("P-") and entry.filename.endswith(".signature"):
                    info["project_id"] = entry.filename.removesuffix(".signature")
                    break

            # Check if password protected (encrypted inner zip exists)
            if info["project_id"]:
                try:
                    zf.getinfo(info["project_id"] + ".zip")
                    info["password_protected"] = True
                except KeyError:
                    # No encrypted inner zip - not password protected
                    pass

                # Try to detect ETS version from project.xml CreatedBy attribute
                try:
                    project_xml = info["project_id"] + "/project.xml"
                    with zf.open(project_xml) as f:
                        # Read first 500 bytes - CreatedBy is in the header
                        header = f.read(500).decode("utf-8", errors="ignore")
                        if 'CreatedBy="ETS4' in header:
                            info["ets_version"] = "ETS4"
                        elif 'CreatedBy="ETS5' in header:
                            info["ets_version"] = "ETS5"
                        elif 'CreatedBy="ETS6' in header:
                            info["ets_version"] = "ETS6"
                except Exception as e:
                    logger.debug(
                        f"Failed to get project_xml: {e}"
                    )  # Fall back to knx_master.xml check

            # Fallback: check knx_master.xml xmlns for schema version
            if info["ets_version"] == "unknown":
                try:
                    with zf.open("knx_master.xml") as f:
                        header = f.read(500).decode("utf-8", errors="ignore")
                        # Schema version 21 = ETS6, 20/14 = ETS5, 13 = ETS4
                        if 'xmlns="http://knx.org/xml/project/21"' in header:
                            info["ets_version"] = "ETS6"
                        elif 'xmlns="http://knx.org/xml/project/20"' in header:
                            info["ets_version"] = "ETS5"
                        elif 'xmlns="http://knx.org/xml/project/14"' in header:
                            info["ets_version"] = "ETS5"
                        elif 'xmlns="http://knx.org/xml/project/13"' in header:
                            info["ets_version"] = "ETS4"
                except Exception as e:
                    logger.debug(f"ETS knx_master.xml parse failed: {e}")  # Fall back to unknown

    except Exception as e:
        module.fail(f"Error reading project file: {e}")

    logger.debug(
        f"knxproj info: project_id={info['project_id']}, "
        f"ets={info['ets_version']}, protected={info['password_protected']}"
    )
    return info


def parse_knxproj(file_path: str, password: Optional[str] = None) -> Dict[str, Any]:
    """Parse .knxproj file and extract project data.

    Args:
        file_path: Path to .knxproj file
        password: Optional password for encrypted projects

    Returns:
        Dict with project data including name, devices, group_addresses,
        communication_objects, topology, locations, and raw_data

    Raises:
        ImportError: If xknxproject is not installed
        Exception: If parsing fails (e.g., invalid password)
    """
    logger.debug(f"Parsing knxproj: {file_path}, password={'set' if password else 'none'}")
    XKNXProj = _get_xknxproject()
    if XKNXProj is None:
        raise ImportError("xknxproject not installed (pip install oida-ics[knx])")

    proj = XKNXProj(Path(file_path), password=password)
    data = proj.parse()

    # Convert TypedDict to regular dict for JSON serialization
    result = {
        "name": data.get("name", "Unknown"),
        "devices": len(data.get("devices", {})),
        "group_addresses": len(data.get("group_addresses", {})),
        "communication_objects": len(data.get("communication_objects", {})),
        "topology": data.get("topology", {}),
        "locations": data.get("locations", {}),
        "raw_data": dict(data),  # Full data for export
    }
    logger.debug(
        f"Parsed: name={result['name']}, devices={result['devices']}, "
        f"group_addrs={result['group_addresses']}"
    )
    return result


def test_knxproj_password(file_path: str, password: str) -> bool:
    """Test if password is valid for .knxproj file.

    Args:
        file_path: Path to .knxproj file
        password: Password to test

    Returns:
        True if password is valid, False otherwise
    """
    XKNXProj = _get_xknxproject()
    InvalidPasswordException = _get_xknxproject_exceptions()

    if XKNXProj is None:
        return False

    try:
        proj = XKNXProj(Path(file_path), password=password)
        proj.parse()
        return True
    except InvalidPasswordException as e:
        logger.debug(f"knxproj password rejected by xknxproject: {e}")
        return False
    except Exception as e:
        logger.debug(f"knxproj parse failed during password test: {e}")
        return False


# ============================================================================
# Password Cracking
# ============================================================================


def crack_knxproj(
    file_path: str,
    wordlist: str,
    *,
    logger,
    threads: int = 16,
    info: Optional[Dict[str, Any]] = None,
    use_fast_mode: bool = False,
) -> Optional[str]:
    """Crack .knxproj password using wordlist with multiprocessing.

    Args:
        file_path: Path to .knxproj file
        wordlist: Path to wordlist file
        logger: NXC-style logger for progress output
        threads: Number of parallel processes (default: 16)
        info: Project info dict (from get_knxproj_info)
        use_fast_mode: If True, use fast ZIP-only test (skips XML parsing)

    Returns:
        Password if found, None otherwise
    """
    logger.debug(f"crack_knxproj: wordlist={wordlist}, threads={threads}, fast={use_fast_mode}")
    try:
        with open(wordlist, "r", errors="ignore") as f:
            passwords = [line.strip() for line in f if line.strip()]
    except Exception as e:
        logger.fail(f"Error reading wordlist: {e}")
        return None

    if not passwords:
        logger.fail("Wordlist is empty")
        return None

    # Get project info if not provided
    if info is None:
        info = get_knxproj_info(file_path)

    mode_str = "FAST (ZIP-only)" if use_fast_mode else "full parse"
    logger.display(f"Testing {len(passwords)} passwords with {threads} processes ({mode_str})...")

    found_password = None
    tested = 0

    # Use multiprocessing Manager for shared stop flag
    manager = Manager()
    stop_flag = manager.Value("b", False)

    # Create argument tuples based on mode
    if use_fast_mode:
        ets_version = info.get("ets_version", "unknown")
        project_id = info.get("project_id", "")
        work_items = [(file_path, pwd, stop_flag, ets_version, project_id) for pwd in passwords]
        test_func = _test_knxproj_password_fast_mp
    else:
        work_items = [(file_path, pwd, stop_flag) for pwd in passwords]
        test_func = _test_knxproj_password_mp

    with ProcessPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(test_func, item): item[1] for item in work_items}
        for future in as_completed(futures):
            tested += 1
            if tested % 100 == 0:
                logger.display(f"Tested {tested}/{len(passwords)} passwords...")
            try:
                result = future.result()
                if result:
                    found_password = result
                    stop_flag.value = True
                    # Cancel remaining futures
                    for f in futures:
                        f.cancel()
                    break
            except Exception as e:
                logger.debug(f"Failed to get result: {e}")
                continue

    logger.display(f"Tested {tested}/{len(passwords)} passwords total")
    return found_password


# ============================================================================
# ETS6 Password Derivation
# ============================================================================


def derive_ets6_zip_password(user_password: str) -> str:
    """Derive the actual ZIP password from user password for ETS6.

    ETS6 uses PBKDF2-HMAC-SHA256 with:
    - Salt: "21.project.ets.knx.org"
    - Iterations: 65536
    - Password encoding: UTF-16-LE
    - Output: Base64 encoded

    Args:
        user_password: User-provided password

    Returns:
        Derived ZIP password (Base64 encoded)
    """
    import base64
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"21.project.ets.knx.org",
        iterations=65536,
    )
    derived_key = kdf.derive(user_password.encode("utf-16-le"))
    return base64.b64encode(derived_key).decode("ascii")


# ============================================================================
# Hash Extraction
# ============================================================================


def extract_knxproj_hash(
    file_path: str,
    *,
    logger,
    user_password: Optional[str] = None,
) -> Optional[str]:
    """Extract hash in hashcat-compatible format.

    For ETS5: Extracts inner ZIP and runs zip2john - direct cracking
    For ETS6: Shows derived password approach for two-stage cracking

    Args:
        file_path: Path to .knxproj file
        logger: NXC-style logger for output
        user_password: Optional password to derive ZIP password for ETS6

    Returns:
        Hash string if extracted, None otherwise
    """
    logger.debug(f"Extracting hash from {file_path}")
    info = get_knxproj_info(file_path)

    if not info["password_protected"]:
        logger.display("Project is not password protected - no hash to extract")
        return None

    # Extract inner ZIP
    with ZipFile(file_path) as zf:
        inner_zip_name = info["project_id"] + ".zip"
        try:
            inner_data = zf.read(inner_zip_name)
        except KeyError:
            logger.fail(f"Inner ZIP not found: {inner_zip_name}")
            return None

    # Save inner ZIP to temp file
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
        f.write(inner_data)
        temp_path = f.name

    logger.display(f"ETS Version: {info['ets_version']}")
    logger.display(f"Inner ZIP: {len(inner_data)} bytes")

    hash_part = None

    # Try to run zip2john (use absolute path for security)
    zip2john_path = shutil.which("zip2john")
    if zip2john_path:
        try:
            result = subprocess.run(
                [zip2john_path, temp_path], capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                hash_line = result.stdout.strip()
                # Format: filename:$pkzip2$...$pkzip2$ or $zip2$...$zip2$
                if "$" in hash_line:
                    # Extract just the hash part for hashcat
                    hash_part = hash_line.split(":", 1)[1] if ":" in hash_line else hash_line
                    logger.success("Hash extracted with zip2john")
        except subprocess.TimeoutExpired:
            logger.fail("zip2john timed out")
        except Exception as e:
            logger.fail(f"zip2john error: {e}")
    else:
        logger.display("zip2john not found - install John the Ripper")

    # Clean up temp file
    try:
        os.unlink(temp_path)
    except Exception as e:
        logger.debug(f"os.unlink(temp_path): {e}")  # Ignore cleanup errors

    _display_hash_info(info, hash_part, user_password, inner_data, logger)

    return hash_part


def _display_hash_info(
    info: Dict[str, Any],
    hash_part: Optional[str],
    user_password: Optional[str],
    inner_data: bytes,
    logger,
) -> None:
    """Display hash extraction information and cracking instructions."""
    if info["ets_version"] == "ETS6":
        logger.display("\n" + "=" * 60)
        logger.display("ETS6 Two-Stage Encryption")
        logger.display("=" * 60)
        logger.display("ETS6 derives the ZIP password from user password:")
        logger.display("  ZIP_password = Base64(PBKDF2(user_password))")
        logger.display("  - Algorithm: PBKDF2-HMAC-SHA256")
        logger.display("  - Salt: 21.project.ets.knx.org")
        logger.display("  - Iterations: 65536")
        logger.display("  - Encoding: UTF-16-LE")

        if user_password:
            # Derive and show the actual ZIP password
            try:
                zip_password = derive_ets6_zip_password(user_password)
                logger.display(f"\nDerived ZIP password for '{user_password}':")
                logger.display(f"  {zip_password}")
                logger.display("\nTest with: unzip -P '<derived_password>' inner.zip")
            except Exception as e:
                logger.fail(f"Failed to derive password: {e}")

        logger.display("\n" + "-" * 60)
        logger.display("Cracking Options:")
        logger.display("-" * 60)
        logger.display("1. Use oida built-in cracker (handles derivation):")
        logger.display(f"   oida knx --knxproj {info['file']} --knxproj-wordlist wordlist.txt")
        logger.display("\n2. Generate derived wordlist for hashcat:")
        logger.display('   python3 -c "')
        logger.display("   import sys, base64")
        logger.display("   from cryptography.hazmat.primitives import hashes")
        logger.display("   from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC")
        logger.display("   for pwd in open(sys.argv[1]):")
        logger.display("       pwd = pwd.strip()")
        logger.display(
            "       kdf = PBKDF2HMAC(hashes.SHA256(), 32, b'21.project.ets.knx.org', 65536)"
        )
        logger.display(
            "       pri"  # string continuation for review script  # noqa: E501
            + "nt(base64.b64encode(kdf.derive(pwd.encode('utf-16-le'))).decode())"
        )
        logger.display('   " wordlist.txt > derived_wordlist.txt')
        logger.display("   hashcat -m 13600 hash.txt derived_wordlist.txt")

        if hash_part:
            logger.display("\n" + "-" * 60)
            logger.display("Hash (WinZip AES, mode 13600):")
            logger.display("-" * 60)
            logger.display(hash_part)

    else:
        # ETS5 - direct cracking works
        logger.display("\n" + "=" * 60)
        logger.display("ETS5 ZipCrypto (Direct Cracking)")
        logger.display("=" * 60)
        logger.display("ETS5 uses the user password directly as ZIP password.")
        logger.display("\nCrack with John:")
        logger.display("  john --wordlist=wordlist.txt hash.txt")
        logger.display("\nCrack with Hashcat (mode 17200-17225):")
        logger.display("  hashcat -m 17200 -a 0 hash.txt wordlist.txt")

        if hash_part:
            logger.display("\n" + "-" * 60)
            logger.display("Hash (PKZIP):")
            logger.display("-" * 60)
            logger.display(hash_part)

    if not hash_part:
        # Fallback: save inner ZIP for manual processing
        # Sanitize project_id to prevent path traversal (it comes from ZIP entry names)
        safe_name = Path(info["project_id"]).name  # Strip any path components
        output_path = Path.cwd() / f"{safe_name}.zip"
        output_path.write_bytes(inner_data)
        logger.display(f"\nInner ZIP saved to: {output_path}")
        logger.display(f"Run manually: zip2john {output_path}")


def display_knxproj_data(data: Dict[str, Any], logger) -> None:
    """Display parsed project data.

    Args:
        data: Parsed project data from parse_knxproj()
        logger: Logger for output
    """
    logger.display("\n=== KNX Project Data ===")
    logger.display(f"Project Name: {data.get('name', 'Unknown')}")
    logger.display(f"Devices: {data['devices']}")
    logger.display(f"Group Addresses: {data['group_addresses']}")
    logger.display(f"Communication Objects: {data['communication_objects']}")

    # Show topology summary
    topology = data.get("topology", {})
    if topology:
        logger.display("\n--- Topology ---")
        for area in topology.values():
            area_addr = area.get("address", "?")
            area_name = area.get("name", "Unknown")
            logger.display(f"Area {area_addr}: {area_name}")
            for line in area.get("lines", {}).values():
                line_addr = line.get("address", "?")
                line_name = line.get("name", "")
                device_count = len(line.get("devices", {}))
                logger.display(f"  Line {line_addr}: {line_name} ({device_count} devices)")

    # Show sample group addresses
    raw_data = data.get("raw_data", {})
    group_addresses = raw_data.get("group_addresses", {})
    if group_addresses:
        logger.display("\n--- Group Addresses (sample) ---")
        count = 0
        for ga_id, ga in group_addresses.items():
            if count >= 20:
                remaining = len(group_addresses) - count
                logger.display(f"  ... and {remaining} more")
                break
            ga_addr = ga.get("address", ga_id)
            ga_name = ga.get("name", "")
            ga_dpt = ga.get("dpt", {})
            dpt_str = f" [{ga_dpt.get('main', '?')}.{ga_dpt.get('sub', '?')}]" if ga_dpt else ""
            logger.display(f"  {ga_addr}: {ga_name}{dpt_str}")
            count += 1
