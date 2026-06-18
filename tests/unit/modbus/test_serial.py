"""
Tests for Modbus serial/RTU CLI options.

Tests the following options:
- --serial-port (-s): Serial port path
- --baudrate (-b): Baud rate (default 9600)
- --parity: Parity (N=None, E=Even, O=Odd)
"""

import unittest
import argparse


class MockModbusSerialClient:
    """Mock Modbus serial client for testing"""

    def __init__(self, **kwargs):
        self.port = kwargs.get("port")
        self.baudrate = kwargs.get("baudrate", 9600)
        self.parity = kwargs.get("parity", "N")
        self.connected = False

    def connect(self):
        self.connected = True
        return True

    def close(self):
        self.connected = False


def create_parser():
    """Create a minimal argument parser for testing serial options"""
    from oida.protocols.modbus.proto_args import proto_args

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="protocol")

    # Create parent parser with common args
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument("-v", "--verbose", action="count", default=0)

    # Register modbus protocol
    proto_args(subparsers, [common_parser])

    return parser


class TestSerialArgumentParsing(unittest.TestCase):
    """Test parsing of serial CLI arguments"""

    @classmethod
    def setUpClass(cls):
        cls.parser = create_parser()

    def test_serial_port_short_flag(self):
        """Test -s short flag for serial port"""
        args = self.parser.parse_args(["modbus", "192.168.1.100", "-s", "/dev/ttyUSB0"])
        self.assertEqual(args.serial_port, "/dev/ttyUSB0")

    def test_serial_port_long_flag(self):
        """Test --serial-port long flag"""
        args = self.parser.parse_args(["modbus", "192.168.1.100", "--serial-port", "/dev/ttyS0"])
        self.assertEqual(args.serial_port, "/dev/ttyS0")

    def test_serial_port_default(self):
        """Test serial port defaults to None"""
        args = self.parser.parse_args(["modbus", "192.168.1.100"])
        self.assertIsNone(args.serial_port)

    def test_baudrate_default(self):
        """Test baudrate defaults to 9600"""
        args = self.parser.parse_args(["modbus", "192.168.1.100"])
        self.assertEqual(args.baudrate, 9600)

    def test_baudrate_short_flag(self):
        """Test -b short flag for baudrate"""
        args = self.parser.parse_args(["modbus", "192.168.1.100", "-b", "115200"])
        self.assertEqual(args.baudrate, 115200)

    def test_baudrate_long_flag(self):
        """Test --baudrate long flag"""
        args = self.parser.parse_args(["modbus", "192.168.1.100", "--baudrate", "19200"])
        self.assertEqual(args.baudrate, 19200)

    def test_baudrate_common_values(self):
        """Test common baudrate values"""
        for rate in [4800, 9600, 19200, 38400, 57600, 115200]:
            args = self.parser.parse_args(["modbus", "192.168.1.100", "-b", str(rate)])
            self.assertEqual(args.baudrate, rate)

    def test_parity_default(self):
        """Test parity defaults to N (None)"""
        args = self.parser.parse_args(["modbus", "192.168.1.100"])
        self.assertEqual(args.parity, "N")

    def test_parity_none(self):
        """Test parity N"""
        args = self.parser.parse_args(["modbus", "192.168.1.100", "--parity", "N"])
        self.assertEqual(args.parity, "N")

    def test_parity_even(self):
        """Test parity E (Even)"""
        args = self.parser.parse_args(["modbus", "192.168.1.100", "--parity", "E"])
        self.assertEqual(args.parity, "E")

    def test_parity_odd(self):
        """Test parity O (Odd)"""
        args = self.parser.parse_args(["modbus", "192.168.1.100", "--parity", "O"])
        self.assertEqual(args.parity, "O")

    def test_parity_invalid_value(self):
        """Test invalid parity value is rejected"""
        with self.assertRaises(SystemExit):
            self.parser.parse_args(["modbus", "192.168.1.100", "--parity", "X"])


class TestSerialOptionCombinations(unittest.TestCase):
    """Test valid combinations of serial options"""

    @classmethod
    def setUpClass(cls):
        cls.parser = create_parser()

    def test_typical_rtu_settings(self):
        """Test typical RTU settings: 9600 8N1"""
        args = self.parser.parse_args(
            ["modbus", "192.168.1.100", "-s", "/dev/ttyUSB0", "-b", "9600", "--parity", "N"]
        )
        self.assertEqual(args.serial_port, "/dev/ttyUSB0")
        self.assertEqual(args.baudrate, 9600)
        self.assertEqual(args.parity, "N")

    def test_high_speed_settings(self):
        """Test high speed settings: 115200 8E1"""
        args = self.parser.parse_args(
            ["modbus", "192.168.1.100", "-s", "/dev/ttyUSB0", "-b", "115200", "--parity", "E"]
        )
        self.assertEqual(args.baudrate, 115200)
        self.assertEqual(args.parity, "E")

    def test_serial_port_windows(self):
        """Test Windows COM port format"""
        args = self.parser.parse_args(["modbus", "192.168.1.100", "-s", "COM1"])
        self.assertEqual(args.serial_port, "COM1")

    def test_serial_port_high_com(self):
        """Test high COM port number (COM10+)"""
        args = self.parser.parse_args(["modbus", "192.168.1.100", "-s", "COM15"])
        self.assertEqual(args.serial_port, "COM15")


class TestSerialPortPaths(unittest.TestCase):
    """Test various serial port path formats"""

    @classmethod
    def setUpClass(cls):
        cls.parser = create_parser()

    def test_linux_usb_serial(self):
        """Test Linux USB serial port"""
        args = self.parser.parse_args(["modbus", "192.168.1.100", "-s", "/dev/ttyUSB0"])
        self.assertEqual(args.serial_port, "/dev/ttyUSB0")

    def test_linux_standard_serial(self):
        """Test Linux standard serial port"""
        args = self.parser.parse_args(["modbus", "192.168.1.100", "-s", "/dev/ttyS0"])
        self.assertEqual(args.serial_port, "/dev/ttyS0")

    def test_linux_acm_device(self):
        """Test Linux ACM device (Arduino, etc.)"""
        args = self.parser.parse_args(["modbus", "192.168.1.100", "-s", "/dev/ttyACM0"])
        self.assertEqual(args.serial_port, "/dev/ttyACM0")

    def test_macos_usb_serial(self):
        """Test macOS USB serial port"""
        args = self.parser.parse_args(["modbus", "192.168.1.100", "-s", "/dev/cu.usbserial-A12345"])
        self.assertEqual(args.serial_port, "/dev/cu.usbserial-A12345")

    def test_rfc2217_url(self):
        """Test RFC2217 network serial port"""
        args = self.parser.parse_args(
            ["modbus", "192.168.1.100", "-s", "rfc2217://192.168.1.50:4000"]
        )
        self.assertEqual(args.serial_port, "rfc2217://192.168.1.50:4000")


class TestBaudrateValidation(unittest.TestCase):
    """Test baudrate value validation"""

    @classmethod
    def setUpClass(cls):
        cls.parser = create_parser()

    def test_baudrate_is_integer(self):
        """Test baudrate is stored as integer"""
        args = self.parser.parse_args(["modbus", "192.168.1.100", "-b", "9600"])
        self.assertIsInstance(args.baudrate, int)

    def test_baudrate_custom_value(self):
        """Test non-standard baudrate value"""
        args = self.parser.parse_args(["modbus", "192.168.1.100", "-b", "250000"])
        self.assertEqual(args.baudrate, 250000)


if __name__ == "__main__":
    unittest.main()
