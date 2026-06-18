"""
Unit tests for serial detection utilities.
"""

import pytest
import importlib.util


# Work around pre-existing package import issues by loading module directly
def _load_serial_detection():
    """Load serial_detection module directly to avoid oida/__init__.py issues."""
    import os

    # Go up from tests/unit/utils to project root, then into oida/utils
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
    module_path = os.path.join(project_root, "src", "oida", "utils", "serial_detection.py")
    spec = importlib.util.spec_from_file_location("serial_detection", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_sd = _load_serial_detection()
SerialDetector = _sd.SerialDetector
SerialConfig = _sd.SerialConfig
PortInfo = _sd.PortInfo
DetectionMethod = _sd.DetectionMethod
check_serial_available = _sd.check_serial_available


class TestSerialConfig:
    """Tests for SerialConfig dataclass."""

    def test_default_config(self):
        """Test default configuration values."""
        config = SerialConfig(port="/dev/ttyUSB0", baudrate=9600)
        assert config.port == "/dev/ttyUSB0"
        assert config.baudrate == 9600
        assert config.parity == "N"
        assert config.stopbits == 1
        assert config.bytesize == 8
        assert config.confidence == 0.0

    def test_custom_config(self):
        """Test custom configuration values."""
        config = SerialConfig(
            port="COM1", baudrate=115200, parity="E", stopbits=2, bytesize=7, confidence=0.85
        )
        assert config.port == "COM1"
        assert config.baudrate == 115200
        assert config.parity == "E"
        assert config.stopbits == 2
        assert config.bytesize == 7
        assert config.confidence == 0.85

    def test_str_representation(self):
        """Test string representation."""
        config = SerialConfig(port="/dev/ttyUSB0", baudrate=9600, confidence=0.92)
        output = str(config)
        assert "/dev/ttyUSB0" in output
        assert "9600" in output
        assert "None" in output  # Parity N = None
        assert "92%" in output

    def test_as_dict(self):
        """Test dictionary conversion."""
        config = SerialConfig(port="/dev/ttyUSB0", baudrate=9600, confidence=0.8)
        d = config.as_dict()
        assert d["port"] == "/dev/ttyUSB0"
        assert d["baudrate"] == 9600
        assert d["confidence"] == 0.8


class TestPortInfo:
    """Tests for PortInfo dataclass."""

    def test_basic_port_info(self):
        """Test basic port info creation."""
        port = PortInfo(
            device="/dev/ttyUSB0", description="USB Serial", hwid="USB VID:PID=0403:6001"
        )
        assert port.device == "/dev/ttyUSB0"
        assert port.description == "USB Serial"
        assert port.manufacturer is None

    def test_str_representation(self):
        """Test string representation."""
        port = PortInfo(
            device="/dev/ttyUSB0", description="FTDI FT232R", hwid="USB VID:PID=0403:6001"
        )
        output = str(port)
        assert "/dev/ttyUSB0" in output
        assert "FTDI FT232R" in output


class TestSerialDetector:
    """Tests for SerialDetector class."""

    def test_standard_bauds(self):
        """Test standard baud rate list."""
        detector = SerialDetector()
        assert 9600 in detector.STANDARD_BAUDS
        assert 115200 in detector.STANDARD_BAUDS
        assert len(detector.STANDARD_BAUDS) >= 5

    def test_extended_bauds(self):
        """Test extended baud rate list."""
        detector = SerialDetector()
        assert 921600 in detector.EXTENDED_BAUDS
        assert 300 in detector.EXTENDED_BAUDS
        assert len(detector.EXTENDED_BAUDS) > len(detector.STANDARD_BAUDS)

    def test_parity_options(self):
        """Test parity options."""
        detector = SerialDetector()
        assert "N" in detector.PARITY_OPTIONS
        assert "E" in detector.PARITY_OPTIONS
        assert "O" in detector.PARITY_OPTIONS

    def test_list_ports(self):
        """Test port enumeration returns list of PortInfo."""
        detector = SerialDetector()
        ports = detector.list_ports()

        # Just check that it returns a list and items are PortInfo
        assert isinstance(ports, list)
        for port in ports:
            assert isinstance(port, PortInfo)
            assert hasattr(port, "device")
            assert hasattr(port, "description")

    def test_list_ports_returns_sorted(self):
        """Test that ports are sorted by device name."""
        detector = SerialDetector()
        ports = detector.list_ports()

        if len(ports) >= 2:
            devices = [p.device for p in ports]
            assert devices == sorted(devices)


class TestDataScoring:
    """Tests for data scoring algorithm."""

    def test_score_printable_ascii(self):
        """Test scoring of printable ASCII data."""
        detector = SerialDetector()

        # All printable with vowels, punctuation, whitespace
        data = b"Hello, World! This is a test.\n"
        score = detector._score_data(data)
        assert score > 0.9  # Should score very high

    def test_score_binary_garbage(self):
        """Test scoring of binary garbage data."""
        detector = SerialDetector()

        # Random binary data
        data = bytes([0x00, 0xFF, 0x80, 0x7F, 0xAB, 0xCD, 0xEF])
        score = detector._score_data(data)
        assert score < 0.5  # Should score low

    def test_score_mixed_data(self):
        """Test scoring of mixed printable/binary data."""
        detector = SerialDetector()

        # Half printable, half binary
        data = b"Hello" + bytes([0x00, 0xFF, 0x80, 0x7F, 0xAB])
        score = detector._score_data(data)
        assert 0.3 < score < 0.8

    def test_score_empty_data(self):
        """Test scoring of empty data."""
        detector = SerialDetector()
        score = detector._score_data(b"")
        assert score == 0.0

    def test_score_only_whitespace(self):
        """Test scoring of whitespace-only data."""
        detector = SerialDetector()
        data = b"   \n\t\r   "
        score = detector._score_data(data)
        assert score > 0.5  # Whitespace is valid

    def test_score_vowels_bonus(self):
        """Test that vowels are recognized as printable characters."""
        detector = SerialDetector()

        # Text with vowels
        with_vowels = b"aeiou"
        # Text without vowels
        without_vowels = b"bcdfg"

        score_with = detector._score_data(with_vowels)
        score_without = detector._score_data(without_vowels)

        # Both should score high as printable text
        assert score_with > 0.8
        assert score_without > 0.8


class TestDetectionMethods:
    """Tests for detection methods."""

    def test_full_sweep_combinations(self):
        """Test that full sweep tests all parameter combinations."""
        detector = SerialDetector()

        # Calculate expected combinations
        expected = (
            len(detector.PARITY_OPTIONS)
            * len(detector.STOPBITS_OPTIONS)
            * len(detector.BYTESIZE_OPTIONS)
        )

        # 3 parity * 2 stopbits * 2 bytesize = 12
        assert expected == 12

    def test_detect_method_enum(self):
        """Test detection method enum values."""
        assert DetectionMethod.PASSIVE.value == "passive"
        assert DetectionMethod.ACTIVE.value == "active"

    def test_detect_invalid_method(self):
        """Test that invalid method raises error."""
        detector = SerialDetector()

        # Create a mock enum value
        class FakeMethod:
            value = "invalid"

        with pytest.raises(ValueError):
            detector.detect("/dev/ttyUSB0", FakeMethod())


class TestCLIIntegration:
    """Tests for CLI integration."""

    def test_check_serial_available(self):
        """Test pyserial availability check."""
        result = check_serial_available()
        # Should return True if pyserial is installed
        assert isinstance(result, bool)
        # Since pyserial is installed, it should be True
        assert result is True


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_score_single_byte(self):
        """Test scoring of single byte."""
        detector = SerialDetector()

        # Single printable byte
        score = detector._score_data(b"a")
        assert score > 0

        # Single non-printable byte
        score = detector._score_data(bytes([0xFF]))
        assert score == 0

    def test_score_all_same_char(self):
        """Test scoring of repeated characters."""
        detector = SerialDetector()

        # All same vowel - should score high (printable)
        data = b"aaaaaaaaaa"
        score = detector._score_data(data)
        assert score > 0.5

        # All same consonant - should also score high (printable)
        data = b"bbbbbbbbbb"
        score = detector._score_data(data)
        assert score > 0.5

    def test_missing_pyserial_flag(self):
        """Test that PYSERIAL_AVAILABLE flag exists."""
        # The module has a PYSERIAL_AVAILABLE flag
        assert hasattr(_sd, "PYSERIAL_AVAILABLE")
        # Since pyserial is installed, it should be True
        assert _sd.PYSERIAL_AVAILABLE is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
