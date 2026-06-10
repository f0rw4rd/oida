#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for KNX ETS project file parsing and password cracking.

Tests the oida.protocols.knx.ets module which handles:
- .knxproj file info extraction
- ETS version detection (ETS4/5/6)
- Password protection detection
- Password validation
- Fast password testing (ZIP-only)
- PBKDF2 key derivation for ETS6
- Hash extraction (hashcat/john format)
- Multiprocessing password cracking
"""

import io
import sys
from unittest.mock import Mock, patch, MagicMock
from zipfile import ZipFile

import pytest

# We need to mock the scanner module registration before importing the knx package
# The scanner.py tries to register during import which fails if decorators not set up

# First, let's set up a mock for the protocol registry
sys.modules.setdefault("oida.utils.protocol_registry", MagicMock())

# Mock the scanner module to avoid registration issues during import
_mock_scanner_module = MagicMock()
_mock_scanner_module.KNXScanner = MagicMock()
_mock_scanner_module.metadata = {}
_mock_scanner_module.run = MagicMock()


# ============================================================================
# Helper function to import ets module safely
# ============================================================================


def get_ets_module():
    """Import ets module with mocked dependencies to avoid full package loading."""
    # We need to patch before importing
    with patch.dict(
        sys.modules,
        {
            "oida.protocols.knx.scanner": _mock_scanner_module,
        },
    ):
        # Import directly from the ets module file
        from oida.protocols.knx import ets

        return ets


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def mock_knxproj_ets5(tmp_path):
    """Create a mock ETS5 .knxproj file structure."""
    knxproj_path = tmp_path / "test_project.knxproj"

    with ZipFile(knxproj_path, "w") as zf:
        # Add signature file to identify project
        zf.writestr("P-1234.signature", b"signature_data")
        # Add project.xml with ETS5 identifier
        project_xml = b'<?xml version="1.0"?><Project CreatedBy="ETS5.7.6" />'
        zf.writestr("P-1234/project.xml", project_xml)
        # Add knx_master.xml with schema version 14 (ETS5)
        knx_master = b'<?xml version="1.0"?><KNX xmlns="http://knx.org/xml/project/14" />'
        zf.writestr("knx_master.xml", knx_master)

    return str(knxproj_path)


@pytest.fixture
def mock_knxproj_ets6(tmp_path):
    """Create a mock ETS6 .knxproj file structure."""
    knxproj_path = tmp_path / "test_project_ets6.knxproj"

    with ZipFile(knxproj_path, "w") as zf:
        # Add signature file to identify project
        zf.writestr("P-5678.signature", b"signature_data")
        # Add project.xml with ETS6 identifier
        project_xml = b'<?xml version="1.0"?><Project CreatedBy="ETS6.1.0" />'
        zf.writestr("P-5678/project.xml", project_xml)
        # Add knx_master.xml with schema version 21 (ETS6)
        knx_master = b'<?xml version="1.0"?><KNX xmlns="http://knx.org/xml/project/21" />'
        zf.writestr("knx_master.xml", knx_master)

    return str(knxproj_path)


@pytest.fixture
def mock_knxproj_ets4(tmp_path):
    """Create a mock ETS4 .knxproj file structure."""
    knxproj_path = tmp_path / "test_project_ets4.knxproj"

    with ZipFile(knxproj_path, "w") as zf:
        # Add signature file to identify project
        zf.writestr("P-0001.signature", b"signature_data")
        # Add project.xml with ETS4 identifier
        project_xml = b'<?xml version="1.0"?><Project CreatedBy="ETS4.2.1" />'
        zf.writestr("P-0001/project.xml", project_xml)
        # Add knx_master.xml with schema version 13 (ETS4)
        knx_master = b'<?xml version="1.0"?><KNX xmlns="http://knx.org/xml/project/13" />'
        zf.writestr("knx_master.xml", knx_master)

    return str(knxproj_path)


@pytest.fixture
def mock_knxproj_password_protected(tmp_path):
    """Create a mock password-protected .knxproj file."""
    knxproj_path = tmp_path / "protected_project.knxproj"

    with ZipFile(knxproj_path, "w") as zf:
        # Add signature file
        zf.writestr("P-ABCD.signature", b"signature_data")
        # Add project.xml
        project_xml = b'<?xml version="1.0"?><Project CreatedBy="ETS5.7.6" />'
        zf.writestr("P-ABCD/project.xml", project_xml)
        # Add encrypted inner ZIP (password protected indicator)
        zf.writestr("P-ABCD.zip", b"encrypted_zip_placeholder")
        # Add knx_master.xml
        knx_master = b'<?xml version="1.0"?><KNX xmlns="http://knx.org/xml/project/14" />'
        zf.writestr("knx_master.xml", knx_master)

    return str(knxproj_path)


@pytest.fixture
def mock_wordlist(tmp_path):
    """Create a mock wordlist file for password testing."""
    wordlist_path = tmp_path / "wordlist.txt"
    passwords = ["password123", "admin", "knx", "secret", "test123", "correct_password"]
    wordlist_path.write_text("\n".join(passwords))
    return str(wordlist_path)


@pytest.fixture
def empty_wordlist(tmp_path):
    """Create an empty wordlist file."""
    wordlist_path = tmp_path / "empty_wordlist.txt"
    wordlist_path.write_text("")
    return str(wordlist_path)


@pytest.fixture(scope="module")
def ets():
    """Get the ets module with mocked dependencies.

    Module-scoped to avoid re-importing per test (~1.1s each).
    Tests use patch.object() for per-test isolation.
    """
    return get_ets_module()


# ============================================================================
# Test: get_knxproj_info()
# ============================================================================


class TestGetKnxprojInfo:
    """Test get_knxproj_info() function."""

    def test_ets5_version_detection(self, ets, mock_knxproj_ets5):
        """Test ETS5 version detection from project.xml CreatedBy attribute."""
        info = ets.get_knxproj_info(mock_knxproj_ets5)

        assert info["file"] == mock_knxproj_ets5
        assert info["ets_version"] == "ETS5"
        assert info["project_id"] == "P-1234"
        assert info["password_protected"] is False

    def test_ets6_version_detection(self, ets, mock_knxproj_ets6):
        """Test ETS6 version detection from project.xml CreatedBy attribute."""
        info = ets.get_knxproj_info(mock_knxproj_ets6)

        assert info["file"] == mock_knxproj_ets6
        assert info["ets_version"] == "ETS6"
        assert info["project_id"] == "P-5678"
        assert info["password_protected"] is False

    def test_ets4_version_detection(self, ets, mock_knxproj_ets4):
        """Test ETS4 version detection from project.xml CreatedBy attribute."""
        info = ets.get_knxproj_info(mock_knxproj_ets4)

        assert info["file"] == mock_knxproj_ets4
        assert info["ets_version"] == "ETS4"
        assert info["project_id"] == "P-0001"
        assert info["password_protected"] is False

    def test_password_protected_detection(self, ets, mock_knxproj_password_protected):
        """Test password protection detection (inner .zip exists)."""
        info = ets.get_knxproj_info(mock_knxproj_password_protected)

        assert info["password_protected"] is True
        assert info["project_id"] == "P-ABCD"

    def test_version_fallback_to_knx_master(self, ets, tmp_path):
        """Test version detection fallback to knx_master.xml when project.xml lacks version."""
        knxproj_path = tmp_path / "fallback_test.knxproj"

        with ZipFile(knxproj_path, "w") as zf:
            zf.writestr("P-TEST.signature", b"signature")
            # project.xml without CreatedBy
            zf.writestr("P-TEST/project.xml", b'<?xml version="1.0"?><Project />')
            # knx_master.xml with schema version 20 (ETS5)
            knx_master = b'<?xml version="1.0"?><KNX xmlns="http://knx.org/xml/project/20" />'
            zf.writestr("knx_master.xml", knx_master)

        info = ets.get_knxproj_info(str(knxproj_path))

        assert info["ets_version"] == "ETS5"

    def test_unknown_version_when_no_indicators(self, ets, tmp_path):
        """Test that version is 'unknown' when no version indicators are present."""
        knxproj_path = tmp_path / "unknown_version.knxproj"

        with ZipFile(knxproj_path, "w") as zf:
            zf.writestr("P-XXXX.signature", b"signature")
            zf.writestr("P-XXXX/project.xml", b'<?xml version="1.0"?><Project />')
            # knx_master.xml without xmlns version
            zf.writestr("knx_master.xml", b'<?xml version="1.0"?><KNX />')

        info = ets.get_knxproj_info(str(knxproj_path))

        assert info["ets_version"] == "unknown"

    def test_missing_signature_file(self, ets, tmp_path):
        """Test handling when no .signature file is present."""
        knxproj_path = tmp_path / "no_signature.knxproj"

        with ZipFile(knxproj_path, "w") as zf:
            zf.writestr("some_other_file.txt", b"data")

        info = ets.get_knxproj_info(str(knxproj_path))

        assert info["project_id"] is None
        assert info["password_protected"] is False

    def test_invalid_zip_file(self, ets, tmp_path):
        """Test handling of invalid/corrupted ZIP file."""
        invalid_path = tmp_path / "invalid.knxproj"
        invalid_path.write_bytes(b"not a valid zip file")

        with patch.object(ets, "module") as mock_module:
            ets.get_knxproj_info(str(invalid_path))

            # Should call module.fail with error message
            mock_module.fail.assert_called_once()
            assert "Error reading" in mock_module.fail.call_args[0][0]

    def test_nonexistent_file(self, ets):
        """Test handling of non-existent file."""
        with patch.object(ets, "module") as mock_module:
            ets.get_knxproj_info("/nonexistent/path/project.knxproj")

            mock_module.fail.assert_called_once()


# ============================================================================
# Test: parse_knxproj()
# ============================================================================


class TestParseKnxproj:
    """Test parse_knxproj() function."""

    def test_successful_parse(self, ets, mock_knxproj_ets5):
        """Test successful project parsing."""
        mock_xknxproj = Mock()
        mock_instance = Mock()
        mock_xknxproj.return_value = mock_instance
        mock_instance.parse.return_value = {
            "name": "Test Project",
            "devices": {"dev1": {}, "dev2": {}},
            "group_addresses": {"0/0/1": {}, "0/0/2": {}, "0/0/3": {}},
            "communication_objects": {"obj1": {}},
            "topology": {"area1": {"lines": {}}},
            "locations": {"building1": {}},
        }

        with patch.object(ets, "_get_xknxproject", return_value=mock_xknxproj):
            result = ets.parse_knxproj(mock_knxproj_ets5)

            assert result["name"] == "Test Project"
            assert result["devices"] == 2
            assert result["group_addresses"] == 3
            assert result["communication_objects"] == 1
            assert "topology" in result
            assert "locations" in result
            assert "raw_data" in result

    def test_parse_with_password(self, ets, mock_knxproj_password_protected):
        """Test parsing password-protected project with valid password."""
        mock_xknxproj = Mock()
        mock_instance = Mock()
        mock_xknxproj.return_value = mock_instance
        mock_instance.parse.return_value = {
            "name": "Protected Project",
            "devices": {},
            "group_addresses": {},
            "communication_objects": {},
            "topology": {},
            "locations": {},
        }

        with patch.object(ets, "_get_xknxproject", return_value=mock_xknxproj):
            ets.parse_knxproj(mock_knxproj_password_protected, password="secret123")

            mock_xknxproj.assert_called_once()
            # Verify password was passed
            call_args = mock_xknxproj.call_args
            assert call_args[1]["password"] == "secret123"

    def test_parse_xknxproject_not_installed(self, ets, mock_knxproj_ets5):
        """Test ImportError when xknxproject is not installed."""
        with patch.object(ets, "_get_xknxproject", return_value=None):
            with pytest.raises(ImportError) as exc_info:
                ets.parse_knxproj(mock_knxproj_ets5)

            assert "xknxproject not installed" in str(exc_info.value)

    def test_parse_invalid_password(self, ets, mock_knxproj_password_protected):
        """Test parsing with invalid password raises exception."""
        mock_xknxproj = Mock()
        mock_instance = Mock()
        mock_xknxproj.return_value = mock_instance
        mock_instance.parse.side_effect = Exception("Invalid password")

        with patch.object(ets, "_get_xknxproject", return_value=mock_xknxproj):
            with pytest.raises(Exception) as exc_info:
                ets.parse_knxproj(mock_knxproj_password_protected, password="wrong_password")

            assert "Invalid password" in str(exc_info.value)


# ============================================================================
# Test: test_knxproj_password()
# ============================================================================


class TestTestKnxprojPassword:
    """Test test_knxproj_password() function."""

    def test_valid_password(self, ets, mock_knxproj_ets5):
        """Test that valid password returns True."""
        mock_xknxproj = Mock()
        mock_instance = Mock()
        mock_xknxproj.return_value = mock_instance
        mock_instance.parse.return_value = {}

        with patch.object(ets, "_get_xknxproject", return_value=mock_xknxproj):
            with patch.object(ets, "_get_xknxproject_exceptions", return_value=Exception):
                result = ets.test_knxproj_password(mock_knxproj_ets5, "correct_password")

                assert result is True

    def test_invalid_password(self, ets, mock_knxproj_ets5):
        """Test that invalid password returns False."""

        class InvalidPasswordException(Exception):
            pass

        mock_xknxproj = Mock()
        mock_instance = Mock()
        mock_xknxproj.return_value = mock_instance
        mock_instance.parse.side_effect = InvalidPasswordException("Wrong password")

        with patch.object(ets, "_get_xknxproject", return_value=mock_xknxproj):
            with patch.object(
                ets, "_get_xknxproject_exceptions", return_value=InvalidPasswordException
            ):
                result = ets.test_knxproj_password(mock_knxproj_ets5, "wrong_password")

                assert result is False

    def test_xknxproject_not_installed(self, ets, mock_knxproj_ets5):
        """Test returns False when xknxproject is not installed."""
        with patch.object(ets, "_get_xknxproject", return_value=None):
            result = ets.test_knxproj_password(mock_knxproj_ets5, "any_password")

            assert result is False

    def test_generic_exception(self, ets, mock_knxproj_ets5):
        """Test returns False on generic exception."""
        mock_xknxproj = Mock()
        mock_instance = Mock()
        mock_xknxproj.return_value = mock_instance
        mock_instance.parse.side_effect = RuntimeError("Unexpected error")

        with patch.object(ets, "_get_xknxproject", return_value=mock_xknxproj):
            with patch.object(ets, "_get_xknxproject_exceptions", return_value=Exception):
                result = ets.test_knxproj_password(mock_knxproj_ets5, "password")

                assert result is False


# ============================================================================
# Test: test_knxproj_password_fast()
# ============================================================================


class TestTestKnxprojPasswordFast:
    """Test test_knxproj_password_fast() function."""

    def test_valid_password_ets5(self, ets, tmp_path):
        """Test fast password validation for ETS5 (direct password)."""
        # Create a proper mock knxproj with inner zip
        knxproj_path = tmp_path / "test.knxproj"

        # Create inner zip content
        inner_zip_buffer = io.BytesIO()
        with ZipFile(inner_zip_buffer, "w") as inner_zf:
            inner_zf.writestr("test_file.xml", b"<test />")
        inner_zip_data = inner_zip_buffer.getvalue()

        # Create outer knxproj
        with ZipFile(knxproj_path, "w") as zf:
            zf.writestr("P-TEST.signature", b"sig")
            zf.writestr("P-TEST/project.xml", b'<?xml version="1.0"?><Project CreatedBy="ETS5" />')
            zf.writestr("P-TEST.zip", inner_zip_data)

        # Mock pyzipper
        mock_pyzipper = Mock()
        mock_aes_zip = Mock()
        mock_aes_zip.__enter__ = Mock(return_value=mock_aes_zip)
        mock_aes_zip.__exit__ = Mock(return_value=False)
        mock_aes_zip.namelist.return_value = ["test_file.xml"]
        mock_aes_zip.read.return_value = b"<test />"
        mock_pyzipper.AESZipFile.return_value = mock_aes_zip

        with patch.object(ets, "_get_pyzipper", return_value=mock_pyzipper):
            info = {
                "project_id": "P-TEST",
                "ets_version": "ETS5",
            }

            result = ets.test_knxproj_password_fast(str(knxproj_path), "test_password", info)

            assert result is True
            mock_aes_zip.setpassword.assert_called_once_with(b"test_password")

    def test_fallback_when_pyzipper_not_available(self, ets, mock_knxproj_ets5):
        """Test fallback to full test when pyzipper is not available."""
        with patch.object(ets, "_get_pyzipper", return_value=None):
            with patch.object(ets, "test_knxproj_password", return_value=True) as mock_test:
                info = {"project_id": "P-1234", "ets_version": "ETS5"}

                result = ets.test_knxproj_password_fast(mock_knxproj_ets5, "password", info)

                assert result is True
                mock_test.assert_called_once_with(mock_knxproj_ets5, "password")

    def test_invalid_password_returns_false(self, ets, tmp_path):
        """Test that invalid password returns False."""
        knxproj_path = tmp_path / "test.knxproj"

        inner_zip_buffer = io.BytesIO()
        with ZipFile(inner_zip_buffer, "w") as inner_zf:
            inner_zf.writestr("test.xml", b"data")

        with ZipFile(knxproj_path, "w") as zf:
            zf.writestr("P-TEST.signature", b"sig")
            zf.writestr("P-TEST.zip", inner_zip_buffer.getvalue())

        # Mock pyzipper to raise decryption error
        mock_pyzipper = Mock()
        mock_aes_zip = Mock()
        mock_aes_zip.__enter__ = Mock(return_value=mock_aes_zip)
        mock_aes_zip.__exit__ = Mock(return_value=False)
        mock_aes_zip.namelist.side_effect = Exception("Bad password")
        mock_pyzipper.AESZipFile.return_value = mock_aes_zip

        with patch.object(ets, "_get_pyzipper", return_value=mock_pyzipper):
            info = {"project_id": "P-TEST", "ets_version": "ETS5"}

            result = ets.test_knxproj_password_fast(str(knxproj_path), "wrong_password", info)

            assert result is False


# ============================================================================
# Test: derive_ets6_zip_password()
# ============================================================================


class TestDeriveEts6ZipPassword:
    """Test derive_ets6_zip_password() function."""

    def test_derivation_returns_base64_string(self, ets):
        """Test that derivation returns a Base64 encoded string."""
        result = ets.derive_ets6_zip_password("test_password")

        # Result should be a valid Base64 string
        assert isinstance(result, str)
        # Base64 encoded 32 bytes = 44 characters
        assert len(result) == 44

    def test_derivation_is_deterministic(self, ets):
        """Test that the same password always produces the same result."""
        result1 = ets.derive_ets6_zip_password("same_password")
        result2 = ets.derive_ets6_zip_password("same_password")

        assert result1 == result2

    def test_different_passwords_produce_different_results(self, ets):
        """Test that different passwords produce different derived keys."""
        result1 = ets.derive_ets6_zip_password("password1")
        result2 = ets.derive_ets6_zip_password("password2")

        assert result1 != result2

    def test_empty_password(self, ets):
        """Test derivation with empty password."""
        result = ets.derive_ets6_zip_password("")

        assert isinstance(result, str)
        assert len(result) == 44

    def test_unicode_password(self, ets):
        """Test derivation with unicode characters in password."""
        result = ets.derive_ets6_zip_password("password")

        assert isinstance(result, str)
        assert len(result) == 44

    def test_salt_and_iterations_compliance(self, ets):
        """Test that PBKDF2 uses correct salt and iteration count for ETS6."""
        import base64

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        password = "test"

        # Manually derive using known ETS6 parameters
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"21.project.ets.knx.org",
            iterations=65536,
        )
        expected = base64.b64encode(kdf.derive(password.encode("utf-16-le"))).decode("ascii")

        result = ets.derive_ets6_zip_password(password)

        assert result == expected


# ============================================================================
# Test: crack_knxproj()
# ============================================================================


class TestCrackKnxproj:
    """Test crack_knxproj() function."""

    def test_empty_wordlist(self, ets, mock_knxproj_ets5, empty_wordlist):
        """Test handling of empty wordlist."""
        mock_logger = Mock()

        result = ets.crack_knxproj(mock_knxproj_ets5, empty_wordlist, logger=mock_logger)

        assert result is None
        mock_logger.fail.assert_called_once()
        assert "empty" in mock_logger.fail.call_args[0][0].lower()

    def test_nonexistent_wordlist(self, ets, mock_knxproj_ets5):
        """Test handling of non-existent wordlist."""
        mock_logger = Mock()

        result = ets.crack_knxproj(
            mock_knxproj_ets5, "/nonexistent/wordlist.txt", logger=mock_logger
        )

        assert result is None
        mock_logger.fail.assert_called_once()

    def test_progress_logging(self, ets, mock_knxproj_ets5, mock_wordlist):
        """Test that progress is logged during cracking."""
        mock_logger = Mock()

        # Run with small wordlist - will complete quickly
        ets.crack_knxproj(mock_knxproj_ets5, mock_wordlist, threads=1, logger=mock_logger)

        # Should at least log start and end
        assert mock_logger.display.called


# ============================================================================
# Test: extract_knxproj_hash()
# ============================================================================


class TestExtractKnxprojHash:
    """Test extract_knxproj_hash() function."""

    def test_hash_extraction_with_zip2john(self, ets, mock_knxproj_password_protected):
        """Test hash extraction using zip2john."""
        mock_logger = Mock()

        with patch.object(ets.shutil, "which", return_value="/usr/bin/zip2john"):
            with patch.object(ets.subprocess, "run") as mock_run:
                mock_run.return_value = Mock(
                    returncode=0,
                    stdout="P-ABCD.zip:$pkzip2$1*2*2*0*24*18*b4a7*8...hash_data...$pkzip2$\n",
                )

                result = ets.extract_knxproj_hash(
                    mock_knxproj_password_protected, logger=mock_logger
                )

                assert result is not None
                assert "$pkzip2$" in result

    def test_hash_extraction_zip2john_not_found(self, ets, mock_knxproj_password_protected):
        """Test behavior when zip2john is not found."""
        mock_logger = Mock()

        with patch.object(ets.shutil, "which", return_value=None):
            result = ets.extract_knxproj_hash(mock_knxproj_password_protected, logger=mock_logger)

            # Should return None but save inner ZIP
            assert result is None
            # Check that appropriate message was logged
            assert any(
                "zip2john not found" in str(call) for call in mock_logger.display.call_args_list
            )

    def test_not_password_protected(self, ets, mock_knxproj_ets5):
        """Test that non-protected project returns None with appropriate message."""
        mock_logger = Mock()

        result = ets.extract_knxproj_hash(mock_knxproj_ets5, logger=mock_logger)

        assert result is None
        assert any(
            "not password protected" in str(call).lower()
            for call in mock_logger.display.call_args_list
        )

    def test_ets6_displays_derivation_info(self, ets, tmp_path):
        """Test that ETS6 hash extraction shows PBKDF2 derivation info."""
        # Create ETS6 password-protected project
        knxproj_path = tmp_path / "ets6_protected.knxproj"

        with ZipFile(knxproj_path, "w") as zf:
            zf.writestr("P-ETS6.signature", b"sig")
            project_xml = b'<?xml version="1.0"?><Project CreatedBy="ETS6.1.0" />'
            zf.writestr("P-ETS6/project.xml", project_xml)
            zf.writestr("P-ETS6.zip", b"encrypted_inner_zip")
            knx_master = b'<?xml version="1.0"?><KNX xmlns="http://knx.org/xml/project/21" />'
            zf.writestr("knx_master.xml", knx_master)

        mock_logger = Mock()

        with patch.object(ets.shutil, "which", return_value="/usr/bin/zip2john"):
            with patch.object(ets.subprocess, "run") as mock_run:
                mock_run.return_value = Mock(
                    returncode=0,
                    stdout="P-ETS6.zip:$zip2$*0*3*0*hash...$zip2$\n",
                )

                ets.extract_knxproj_hash(str(knxproj_path), logger=mock_logger)

                # Check that ETS6 derivation info was displayed
                display_calls = [str(call) for call in mock_logger.display.call_args_list]
                assert any("PBKDF2" in call for call in display_calls)
                assert any("65536" in call for call in display_calls)

    def test_ets6_with_user_password_shows_derived(self, ets, tmp_path):
        """Test that ETS6 extraction with user password shows derived ZIP password."""
        knxproj_path = tmp_path / "ets6_test.knxproj"

        with ZipFile(knxproj_path, "w") as zf:
            zf.writestr("P-DEMO.signature", b"sig")
            project_xml = b'<?xml version="1.0"?><Project CreatedBy="ETS6.1.0" />'
            zf.writestr("P-DEMO/project.xml", project_xml)
            zf.writestr("P-DEMO.zip", b"encrypted")
            knx_master = b'<?xml version="1.0"?><KNX xmlns="http://knx.org/xml/project/21" />'
            zf.writestr("knx_master.xml", knx_master)

        mock_logger = Mock()

        with patch.object(ets.shutil, "which", return_value="/usr/bin/zip2john"):
            with patch.object(ets.subprocess, "run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout="hash_output\n")

                ets.extract_knxproj_hash(
                    str(knxproj_path), user_password="mypassword", logger=mock_logger
                )

                # Check that derived password was displayed
                display_calls = [str(call) for call in mock_logger.display.call_args_list]
                assert any("Derived ZIP password" in call for call in display_calls)

    def test_zip2john_timeout(self, ets, mock_knxproj_password_protected):
        """Test handling of zip2john timeout."""
        import subprocess

        mock_logger = Mock()

        with patch.object(ets.shutil, "which", return_value="/usr/bin/zip2john"):
            with patch.object(ets.subprocess, "run") as mock_run:
                mock_run.side_effect = subprocess.TimeoutExpired(cmd="zip2john", timeout=30)

                result = ets.extract_knxproj_hash(
                    mock_knxproj_password_protected, logger=mock_logger
                )

                assert result is None
                mock_logger.fail.assert_called()
                assert "timed out" in mock_logger.fail.call_args[0][0].lower()


# ============================================================================
# Test: display_knxproj_data()
# ============================================================================


class TestDisplayKnxprojData:
    """Test display_knxproj_data() function."""

    def test_basic_display(self, ets):
        """Test basic project data display."""
        mock_logger = Mock()

        data = {
            "name": "Test Building",
            "devices": 15,
            "group_addresses": 100,
            "communication_objects": 50,
            "topology": {},
            "locations": {},
            "raw_data": {},
        }

        ets.display_knxproj_data(data, mock_logger)

        # Verify key information was displayed
        display_calls = [str(call) for call in mock_logger.display.call_args_list]
        assert any("Test Building" in call for call in display_calls)
        assert any("15" in call for call in display_calls)  # devices
        assert any("100" in call for call in display_calls)  # group addresses

    def test_display_with_topology(self, ets):
        """Test display with topology information."""
        mock_logger = Mock()

        data = {
            "name": "Office Building",
            "devices": 20,
            "group_addresses": 150,
            "communication_objects": 75,
            "topology": {
                "area1": {
                    "address": "1",
                    "name": "Ground Floor",
                    "lines": {
                        "line1": {
                            "address": "1.1",
                            "name": "Lighting",
                            "devices": {"dev1": {}, "dev2": {}},
                        }
                    },
                }
            },
            "locations": {},
            "raw_data": {},
        }

        ets.display_knxproj_data(data, mock_logger)

        display_calls = [str(call) for call in mock_logger.display.call_args_list]
        assert any("Ground Floor" in call for call in display_calls)
        assert any("Lighting" in call for call in display_calls)

    def test_display_with_group_addresses_sample(self, ets):
        """Test display shows sample of group addresses."""
        mock_logger = Mock()

        # Create data with more than 20 group addresses
        group_addresses = {}
        for i in range(30):
            group_addresses[f"ga_{i}"] = {
                "address": f"0/0/{i}",
                "name": f"Address_{i}",
                "dpt": {"main": 1, "sub": 1},
            }

        data = {
            "name": "Large Project",
            "devices": 100,
            "group_addresses": 30,
            "communication_objects": 150,
            "topology": {},
            "locations": {},
            "raw_data": {"group_addresses": group_addresses},
        }

        ets.display_knxproj_data(data, mock_logger)

        display_calls = [str(call) for call in mock_logger.display.call_args_list]
        # Should show "... and X more"
        assert any("more" in call.lower() for call in display_calls)


# ============================================================================
# Test: Multiprocessing worker functions
# ============================================================================


class TestMultiprocessingWorkers:
    """Test multiprocessing worker functions."""

    def test_test_knxproj_password_mp_valid(self, ets, mock_knxproj_ets5):
        """Test _test_knxproj_password_mp with valid password."""
        mock_xknxproj = Mock()
        mock_instance = Mock()
        mock_xknxproj.return_value = mock_instance
        mock_instance.parse.return_value = {}

        with patch.object(ets, "_get_xknxproject", return_value=mock_xknxproj):
            stop_flag = Mock()
            stop_flag.value = False

            result = ets._test_knxproj_password_mp((mock_knxproj_ets5, "valid_password", stop_flag))

            assert result == "valid_password"

    def test_test_knxproj_password_mp_invalid(self, ets, mock_knxproj_ets5):
        """Test _test_knxproj_password_mp with invalid password."""
        mock_xknxproj = Mock()
        mock_instance = Mock()
        mock_xknxproj.return_value = mock_instance
        mock_instance.parse.side_effect = Exception("Invalid password")

        with patch.object(ets, "_get_xknxproject", return_value=mock_xknxproj):
            stop_flag = Mock()
            stop_flag.value = False

            result = ets._test_knxproj_password_mp(
                (mock_knxproj_ets5, "invalid_password", stop_flag)
            )

            assert result is None

    def test_test_knxproj_password_mp_stop_flag_set(self, ets, mock_knxproj_ets5):
        """Test _test_knxproj_password_mp returns None when stop flag is set."""
        stop_flag = Mock()
        stop_flag.value = True  # Stop flag set

        result = ets._test_knxproj_password_mp((mock_knxproj_ets5, "password", stop_flag))

        assert result is None

    def test_test_knxproj_password_mp_no_xknxproject(self, ets, mock_knxproj_ets5):
        """Test _test_knxproj_password_mp returns None when xknxproject unavailable."""
        with patch.object(ets, "_get_xknxproject", return_value=None):
            stop_flag = Mock()
            stop_flag.value = False

            result = ets._test_knxproj_password_mp((mock_knxproj_ets5, "password", stop_flag))

            assert result is None


# ============================================================================
# Test: Error handling edge cases
# ============================================================================


class TestErrorHandling:
    """Test error handling edge cases."""

    def test_parse_knxproj_corrupted_xml(self, ets, mock_knxproj_ets5):
        """Test handling of corrupted XML in project file."""

        class XKNXProjMock:
            def __init__(self, path, password=None):
                pass

            def parse(self):
                raise Exception("XML parsing error")

        with patch.object(ets, "_get_xknxproject", return_value=XKNXProjMock):
            with pytest.raises(Exception) as exc_info:
                ets.parse_knxproj(mock_knxproj_ets5)

            assert "XML parsing error" in str(exc_info.value)

    def test_extract_hash_inner_zip_not_found(self, ets, tmp_path):
        """Test hash extraction when inner ZIP is missing (malformed project)."""
        knxproj_path = tmp_path / "malformed.knxproj"

        with ZipFile(knxproj_path, "w") as zf:
            # Mark as password protected but no actual inner zip
            zf.writestr("P-BAD.signature", b"sig")
            zf.writestr("P-BAD/project.xml", b'<Project CreatedBy="ETS5" />')
            # Missing P-BAD.zip!

        mock_logger = Mock()

        # The get_knxproj_info will not mark it as password protected
        # since the inner zip doesn't exist
        result = ets.extract_knxproj_hash(str(knxproj_path), logger=mock_logger)

        assert result is None


# ============================================================================
# Parametrized tests
# ============================================================================


class TestParametrizedVersionDetection:
    """Parametrized tests for ETS version detection."""

    @pytest.mark.parametrize(
        "created_by,expected_version",
        [
            ("ETS4.0.0", "ETS4"),
            ("ETS4.2.1", "ETS4"),
            ("ETS5.0.0", "ETS5"),
            ("ETS5.7.6", "ETS5"),
            ("ETS6.0.0", "ETS6"),
            ("ETS6.1.0", "ETS6"),
        ],
    )
    def test_version_from_created_by(self, ets, tmp_path, created_by, expected_version):
        """Test version detection from various CreatedBy values."""
        knxproj_path = tmp_path / "test.knxproj"

        with ZipFile(knxproj_path, "w") as zf:
            zf.writestr("P-TEST.signature", b"sig")
            project_xml = f'<?xml version="1.0"?><Project CreatedBy="{created_by}" />'.encode()
            zf.writestr("P-TEST/project.xml", project_xml)

        info = ets.get_knxproj_info(str(knxproj_path))

        assert info["ets_version"] == expected_version

    @pytest.mark.parametrize(
        "schema_version,expected_version",
        [
            ("13", "ETS4"),
            ("14", "ETS5"),
            ("20", "ETS5"),
            ("21", "ETS6"),
        ],
    )
    def test_version_from_schema(self, ets, tmp_path, schema_version, expected_version):
        """Test version detection from knx_master.xml schema version."""
        knxproj_path = tmp_path / "test.knxproj"

        with ZipFile(knxproj_path, "w") as zf:
            zf.writestr("P-TEST.signature", b"sig")
            # project.xml without CreatedBy (forces fallback)
            zf.writestr("P-TEST/project.xml", b'<?xml version="1.0"?><Project />')
            knx_master = f'<?xml version="1.0"?><KNX xmlns="http://knx.org/xml/project/{schema_version}" />'.encode()
            zf.writestr("knx_master.xml", knx_master)

        info = ets.get_knxproj_info(str(knxproj_path))

        assert info["ets_version"] == expected_version


class TestParametrizedPasswordTests:
    """Parametrized tests for password testing."""

    @pytest.mark.parametrize(
        "password",
        [
            "",
            "a",
            "short",
            "medium_length_password",
            "very_long_password_that_exceeds_typical_limits_but_should_still_work",
            "password with spaces",
            "password\twith\ttabs",
            "password\nwith\nnewlines",
        ],
    )
    def test_password_formats(self, ets, mock_knxproj_ets5, password):
        """Test various password formats."""
        mock_xknxproj = Mock()
        mock_instance = Mock()
        mock_xknxproj.return_value = mock_instance
        mock_instance.parse.return_value = {}

        with patch.object(ets, "_get_xknxproject", return_value=mock_xknxproj):
            with patch.object(ets, "_get_xknxproject_exceptions", return_value=Exception):
                result = ets.test_knxproj_password(mock_knxproj_ets5, password)

                # Should not crash, should return True (mocked success)
                assert result is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
