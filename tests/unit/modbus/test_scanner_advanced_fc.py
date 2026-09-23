#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for Modbus advanced function codes.

Tests file records (FC 20/21), mask write (FC 22),
atomic read/write (FC 23), and FIFO queue (FC 24).
"""

import pytest
from unittest.mock import MagicMock, patch

# Check for pymodbus availability
from tests.service_gate import require_import

require_import("pymodbus", reason="pymodbus library not installed")

from oida.protocols.modbus.scanner import ModbusExceptionCode


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def mock_client():
    """Create a mock Modbus client with advanced FC responses."""
    client = MagicMock()

    # Mock read_file_record (FC 20) response
    file_read_response = MagicMock()
    file_read_response.isError.return_value = False
    file_read_response.records = [
        MagicMock(record_data=[100, 200, 300, 400, 500]),
    ]
    client.read_file_record.return_value = file_read_response

    # Mock write_file_record (FC 21) response
    file_write_response = MagicMock()
    file_write_response.isError.return_value = False
    client.write_file_record.return_value = file_write_response

    # Mock mask_write_register (FC 22) response
    mask_write_response = MagicMock()
    mask_write_response.isError.return_value = False
    mask_write_response.address = 0
    mask_write_response.and_mask = 0xFF00
    mask_write_response.or_mask = 0x00FF
    client.mask_write_register.return_value = mask_write_response

    # Mock read_write_multiple_registers (FC 23) response
    rw_response = MagicMock()
    rw_response.isError.return_value = False
    rw_response.registers = [1000, 2000, 3000]
    client.readwrite_registers.return_value = rw_response

    # Mock read_fifo_queue (FC 24) response
    fifo_response = MagicMock()
    fifo_response.isError.return_value = False
    fifo_response.values = [10, 20, 30, 40, 50]
    client.read_fifo_queue.return_value = fifo_response

    return client


@pytest.fixture
def scanner_args():
    """Create default scanner arguments."""
    return {
        "rhost": "192.168.1.100",
        "rport": 502,
        "timeout": 5,
        "unit-id": 1,
    }


def create_mock_scanner(args):
    """Create a mock ModbusScanner instance."""
    from oida.protocols.modbus.scanner import ModbusScanner

    with patch.object(ModbusScanner, "__init__", lambda self, *a, **kw: None):
        scanner = ModbusScanner.__new__(ModbusScanner)
        scanner.args = args
        scanner.host = args.get("rhost", "127.0.0.1")
        scanner.port = args.get("rport", 502)
        scanner.timeout = args.get("timeout", 5)
        scanner.unit_id = args.get("unit-id", 1)
        scanner.logger = MagicMock()
        scanner.security = MagicMock()
        return scanner


# =============================================================================
# Test Read File Record (FC 20)
# =============================================================================


class TestReadFileRecord:
    """Tests for read file record (FC 20)."""

    def test_read_file_record_success(self, mock_client, scanner_args):
        """Test successful file record read."""
        create_mock_scanner(scanner_args)

        # Request format: file_number, record_number, record_length
        result = mock_client.read_file_record(
            [(0x0001, 0x0000, 5)],  # File 1, record 0, 5 registers
            device_id=1,
        )

        assert not result.isError()
        assert len(result.records) == 1
        assert len(result.records[0].record_data) == 5

    def test_read_file_record_multiple(self, mock_client, scanner_args):
        """Test reading multiple file records."""
        file_response = MagicMock()
        file_response.isError.return_value = False
        file_response.records = [
            MagicMock(record_data=[100, 200]),
            MagicMock(record_data=[300, 400]),
        ]
        mock_client.read_file_record.return_value = file_response

        create_mock_scanner(scanner_args)

        result = mock_client.read_file_record(
            [
                (0x0001, 0x0000, 2),  # File 1, record 0
                (0x0001, 0x0001, 2),  # File 1, record 1
            ],
            device_id=1,
        )

        assert not result.isError()
        assert len(result.records) == 2

    def test_read_file_record_not_supported(self, mock_client, scanner_args):
        """Test file record read when not supported translates into a None result."""
        error_response = MagicMock()
        error_response.isError.return_value = True
        error_response.exception_code = ModbusExceptionCode.ILLEGAL_FUNCTION
        mock_client.read_file_record.return_value = error_response

        scanner = create_mock_scanner(scanner_args)

        # record_length is a byte count to pymodbus's FileRecord and must be even;
        # it stores record_length // 2 (register count) after construction.
        result = scanner._read_file_record(
            mock_client, file_number=1, record_number=0, record_length=4
        )

        assert result is None
        call_kwargs = mock_client.read_file_record.call_args.kwargs
        assert call_kwargs["device_id"] == scanner.unit_id
        records = call_kwargs["records"]
        assert len(records) == 1
        assert records[0].file_number == 1
        assert records[0].record_number == 0
        assert records[0].record_length == 2

    def test_read_file_record_invalid_file(self, mock_client, scanner_args):
        """Test file record read with invalid file number builds the request from that file."""
        error_response = MagicMock()
        error_response.isError.return_value = True
        error_response.exception_code = ModbusExceptionCode.ILLEGAL_DATA_ADDRESS
        mock_client.read_file_record.return_value = error_response

        scanner = create_mock_scanner(scanner_args)

        result = scanner._read_file_record(
            mock_client, file_number=0xFFFF, record_number=0, record_length=4
        )

        assert result is None
        records = mock_client.read_file_record.call_args.kwargs["records"]
        assert records[0].file_number == 0xFFFF
        # isError() path returns None without hitting the exception-logging branch
        scanner.logger.debug.assert_not_called()


# =============================================================================
# Test Write File Record (FC 21)
# =============================================================================


class TestWriteFileRecord:
    """Tests for write file record (FC 21)."""

    def test_write_file_record_success(self, mock_client, scanner_args):
        """Test successful file record write reports byte/register counts and the real PDU args."""
        scanner = create_mock_scanner(scanner_args)

        data = bytes([0, 100, 0, 200, 1, 44])  # 3 registers worth of bytes
        result = scanner._write_file_record(mock_client, file_number=1, record_number=0, data=data)

        assert result["success"] is True
        assert result["bytes_written"] == len(data)
        assert result["registers_written"] == 3

        call_kwargs = mock_client.write_file_record.call_args.kwargs
        assert call_kwargs["device_id"] == scanner.unit_id
        records = call_kwargs["records"]
        assert len(records) == 1
        assert records[0].file_number == 1
        assert records[0].record_number == 0
        assert records[0].record_data == data

    def test_write_file_record_multiple(self, mock_client, scanner_args):
        """Odd-length payloads are padded to an even length before being sent on the wire."""
        scanner = create_mock_scanner(scanner_args)

        data = b"\x00\x64\x00\xc8\x01"  # 5 bytes -> padded to 6
        result = scanner._write_file_record(mock_client, file_number=2, record_number=3, data=data)

        assert result["success"] is True
        assert result["bytes_written"] == 6
        assert result["registers_written"] == 3

        records = mock_client.write_file_record.call_args.kwargs["records"]
        assert records[0].record_data == data + b"\x00"

    def test_write_file_record_not_supported(self, mock_client, scanner_args):
        """Test file record write when not supported returns a failed result with no byte count."""
        error_response = MagicMock()
        error_response.isError.return_value = True
        error_response.exception_code = ModbusExceptionCode.ILLEGAL_FUNCTION
        mock_client.write_file_record.return_value = error_response

        scanner = create_mock_scanner(scanner_args)
        result = scanner._write_file_record(
            mock_client, file_number=1, record_number=0, data=b"\x00\x64"
        )

        assert result["success"] is False
        assert result["bytes_written"] == 0
        assert "registers_written" not in result
        assert "Modbus error" in result["error"]

    def test_write_file_record_read_only(self, mock_client, scanner_args):
        """Test file record write to read-only file still reports the requested file/record."""
        error_response = MagicMock()
        error_response.isError.return_value = True
        error_response.exception_code = ModbusExceptionCode.ILLEGAL_DATA_ADDRESS
        mock_client.write_file_record.return_value = error_response

        scanner = create_mock_scanner(scanner_args)
        result = scanner._write_file_record(
            mock_client, file_number=9, record_number=1, data=b"\x00\x64"
        )

        assert result["success"] is False
        assert result["file_number"] == 9
        assert result["record_number"] == 1
        records = mock_client.write_file_record.call_args.kwargs["records"]
        assert records[0].file_number == 9
        assert records[0].record_number == 1


# =============================================================================
# Test Mask Write Register (FC 22)
# =============================================================================


class TestMaskWriteRegister:
    """Tests for mask write register (FC 22)."""

    def test_mask_write_success(self, mock_client, scanner_args):
        """Test successful mask write reads back the new value for verification."""
        mock_client.read_holding_registers.return_value = MagicMock(
            isError=MagicMock(return_value=False), registers=[0x00FF]
        )
        scanner = create_mock_scanner(scanner_args)

        # Mask write: Result = (Current AND And_Mask) OR (Or_Mask AND NOT And_Mask)
        result = scanner._mask_write_register(
            mock_client, address=0, and_mask=0xFF00, or_mask=0x00FF
        )

        assert result["success"] is True
        assert result["new_value"] == 0x00FF
        mock_client.mask_write_register.assert_called_once_with(
            address=0, and_mask=0xFF00, or_mask=0x00FF, device_id=scanner.unit_id
        )
        mock_client.read_holding_registers.assert_called_once_with(
            address=0, count=1, device_id=scanner.unit_id
        )

    def test_mask_write_set_bits(self, mock_client, scanner_args):
        """Test mask write to set specific bits passes the exact masks to the wire call."""
        # To set bit 3: and_mask=0xFFFF, or_mask=0x0008
        mock_client.read_holding_registers.return_value = MagicMock(
            isError=MagicMock(return_value=False), registers=[0x0008]
        )
        scanner = create_mock_scanner(scanner_args)

        result = scanner._mask_write_register(
            mock_client, address=4, and_mask=0xFFFF, or_mask=0x0008
        )

        assert result["success"] is True
        assert result["new_value"] == 0x0008
        mock_client.mask_write_register.assert_called_once_with(
            address=4, and_mask=0xFFFF, or_mask=0x0008, device_id=scanner.unit_id
        )

    def test_mask_write_clear_bits(self, mock_client, scanner_args):
        """Test mask write to clear specific bits passes the exact masks to the wire call."""
        # To clear bit 3: and_mask=0xFFF7, or_mask=0x0000
        mock_client.read_holding_registers.return_value = MagicMock(
            isError=MagicMock(return_value=False), registers=[0x0000]
        )
        scanner = create_mock_scanner(scanner_args)

        result = scanner._mask_write_register(
            mock_client, address=4, and_mask=0xFFF7, or_mask=0x0000
        )

        assert result["success"] is True
        assert result["new_value"] == 0x0000
        mock_client.mask_write_register.assert_called_once_with(
            address=4, and_mask=0xFFF7, or_mask=0x0000, device_id=scanner.unit_id
        )

    def test_mask_write_not_supported(self, mock_client, scanner_args):
        """Test mask write when not supported does not attempt a verification readback."""
        error_response = MagicMock()
        error_response.isError.return_value = True
        error_response.exception_code = ModbusExceptionCode.ILLEGAL_FUNCTION
        mock_client.mask_write_register.return_value = error_response

        scanner = create_mock_scanner(scanner_args)
        result = scanner._mask_write_register(
            mock_client, address=0, and_mask=0xFFFF, or_mask=0x0000
        )

        assert result["success"] is False
        assert "new_value" not in result
        assert "Modbus error" in result["error"]
        mock_client.read_holding_registers.assert_not_called()

    def test_mask_write_invalid_address(self, mock_client, scanner_args):
        """Test mask write with invalid address passes that address through to the wire call."""
        error_response = MagicMock()
        error_response.isError.return_value = True
        error_response.exception_code = ModbusExceptionCode.ILLEGAL_DATA_ADDRESS
        mock_client.mask_write_register.return_value = error_response

        scanner = create_mock_scanner(scanner_args)
        result = scanner._mask_write_register(
            mock_client, address=99999, and_mask=0xFFFF, or_mask=0x0000
        )

        assert result["success"] is False
        assert result["address"] == 99999
        mock_client.mask_write_register.assert_called_once_with(
            address=99999, and_mask=0xFFFF, or_mask=0x0000, device_id=scanner.unit_id
        )


# =============================================================================
# Test Read/Write Multiple Registers (FC 23)
# =============================================================================


class TestAtomicReadWrite:
    """Tests for atomic read/write multiple registers (FC 23)."""

    def test_atomic_read_write_success(self, mock_client, scanner_args):
        """Test successful atomic read/write."""
        create_mock_scanner(scanner_args)

        result = mock_client.readwrite_registers(
            read_address=0,
            read_count=3,
            write_address=10,
            write_registers=[100, 200, 300],
            device_id=1,
        )

        assert not result.isError()
        assert len(result.registers) == 3
        assert result.registers == [1000, 2000, 3000]

    def test_atomic_read_only(self, mock_client, scanner_args):
        """Test atomic operation with read only (empty write) still issues a real PDU."""
        mock_client.readwrite_registers.return_value = MagicMock(
            isError=MagicMock(return_value=False), registers=[10, 20, 30, 40, 50]
        )
        scanner = create_mock_scanner(scanner_args)

        # Some implementations allow read-only by passing empty write
        result = scanner._atomic_read_write(
            mock_client, read_addr=0, read_count=5, write_addr=0, write_data=[]
        )

        assert result["success"] is True
        assert result["read_values"] == [10, 20, 30, 40, 50]
        assert result["write_count"] == 0
        assert result["values_written"] == []
        mock_client.readwrite_registers.assert_called_once_with(
            read_address=0, read_count=5, write_address=0, values=[], device_id=scanner.unit_id
        )

    def test_atomic_read_write_not_supported(self, mock_client, scanner_args):
        """Test atomic read/write when not supported."""
        error_response = MagicMock()
        error_response.isError.return_value = True
        error_response.exception_code = ModbusExceptionCode.ILLEGAL_FUNCTION
        mock_client.readwrite_registers.return_value = error_response

        scanner = create_mock_scanner(scanner_args)
        result = scanner._atomic_read_write(
            mock_client, read_addr=0, read_count=3, write_addr=10, write_data=[100]
        )

        assert result["success"] is False
        assert result["read_values"] == []
        assert "Modbus error" in result["error"]

    def test_atomic_read_write_max_count(self, mock_client, scanner_args):
        """Test atomic read/write with maximum counts."""
        # FC 23 limits: read up to 125, write up to 121 registers
        mock_client.readwrite_registers.return_value = MagicMock(
            isError=MagicMock(return_value=False), registers=list(range(125))
        )
        scanner = create_mock_scanner(scanner_args)
        write_data = list(range(121))

        result = scanner._atomic_read_write(
            mock_client, read_addr=0, read_count=125, write_addr=0, write_data=write_data
        )

        assert result["success"] is True
        assert len(result["read_values"]) == 125
        assert result["read_values"] == list(range(125))
        assert result["write_count"] == 121
        mock_client.readwrite_registers.assert_called_once_with(
            read_address=0,
            read_count=125,
            write_address=0,
            values=write_data,
            device_id=scanner.unit_id,
        )


# =============================================================================
# Test Read FIFO Queue (FC 24)
# =============================================================================


class TestReadFIFOQueue:
    """Tests for read FIFO queue (FC 24)."""

    def test_read_fifo_queue_success(self, mock_client, scanner_args):
        """Test successful FIFO queue read."""
        create_mock_scanner(scanner_args)

        result = mock_client.read_fifo_queue(
            address=0,  # FIFO pointer address
            device_id=1,
        )

        assert not result.isError()
        assert len(result.values) == 5
        assert result.values == [10, 20, 30, 40, 50]

    def test_read_fifo_queue_empty(self, mock_client, scanner_args):
        """Test reading empty FIFO queue."""
        fifo_response = MagicMock()
        fifo_response.isError.return_value = False
        fifo_response.values = []
        mock_client.read_fifo_queue.return_value = fifo_response

        create_mock_scanner(scanner_args)

        result = mock_client.read_fifo_queue(address=0, device_id=1)

        assert not result.isError()
        assert len(result.values) == 0

    def test_read_fifo_queue_full(self, mock_client, scanner_args):
        """Test reading full FIFO queue (31 values max per spec)."""
        fifo_response = MagicMock()
        fifo_response.isError.return_value = False
        fifo_response.values = list(range(31))
        mock_client.read_fifo_queue.return_value = fifo_response

        create_mock_scanner(scanner_args)

        result = mock_client.read_fifo_queue(address=0, device_id=1)

        assert not result.isError()
        assert len(result.values) == 31

    def test_read_fifo_queue_not_supported(self, mock_client, scanner_args):
        """Test FIFO queue read when not supported returns None without raising.

        _read_fifo_queue (FC 24) goes through the generic execute_pdu() path, not a
        dedicated pymodbus client method, so the mock must be wired on client.execute.
        """
        error_response = MagicMock()
        error_response.isError.return_value = True
        error_response.exception_code = ModbusExceptionCode.ILLEGAL_FUNCTION
        mock_client.execute.return_value = error_response

        scanner = create_mock_scanner(scanner_args)
        result = scanner._read_fifo_queue(mock_client, pointer_address=0)

        assert result is None
        call_args = mock_client.execute.call_args.args
        assert call_args[0] is False  # no_response_expected
        pdu = call_args[1]
        assert pdu.dev_id == scanner.unit_id
        assert pdu.function_code == 24

    def test_read_fifo_queue_invalid_address(self, mock_client, scanner_args):
        """Test FIFO queue read with an edge-case pointer address still builds a real PDU."""
        error_response = MagicMock()
        error_response.isError.return_value = True
        error_response.exception_code = ModbusExceptionCode.ILLEGAL_DATA_ADDRESS
        mock_client.execute.return_value = error_response

        scanner = create_mock_scanner(scanner_args)
        result = scanner._read_fifo_queue(mock_client, pointer_address=0xFFFF)

        assert result is None
        pdu = mock_client.execute.call_args.args[1]
        assert pdu.dev_id == scanner.unit_id
        assert pdu.encode() == b"\xff\xff"


# =============================================================================
# Test Advanced FC Argument Parsing
# =============================================================================


class TestAdvancedFCArguments:
    """Tests for advanced FC argument parsing."""

    def test_file_read_argument(self, scanner_args):
        """Test --file-read argument parsing."""
        # Format: FILE:REC[:LEN]
        scanner_args["file-read"] = "1:0:5"
        scanner = create_mock_scanner(scanner_args)

        arg = scanner.args.get("file-read")
        parts = arg.split(":")
        file_num = int(parts[0])
        record_num = int(parts[1])
        length = int(parts[2]) if len(parts) > 2 else 1

        assert file_num == 1
        assert record_num == 0
        assert length == 5

    def test_file_write_argument(self, scanner_args):
        """Test --file-write argument parsing."""
        # Format: FILE:REC:DATA
        scanner_args["file-write"] = "1:0:100,200,300"
        scanner = create_mock_scanner(scanner_args)

        arg = scanner.args.get("file-write")
        parts = arg.split(":")
        file_num = int(parts[0])
        record_num = int(parts[1])
        data = [int(v) for v in parts[2].split(",")]

        assert file_num == 1
        assert record_num == 0
        assert data == [100, 200, 300]

    def test_mask_write_argument(self, scanner_args):
        """Test --mask-write argument parsing."""
        # Format: ADDR:AND:OR
        scanner_args["mask-write"] = "0:0xFF00:0x00FF"
        scanner = create_mock_scanner(scanner_args)

        arg = scanner.args.get("mask-write")
        parts = arg.split(":")
        address = int(parts[0])
        and_mask = int(parts[1], 16)
        or_mask = int(parts[2], 16)

        assert address == 0
        assert and_mask == 0xFF00
        assert or_mask == 0x00FF

    def test_atomic_rw_argument(self, scanner_args):
        """Test --atomic-rw argument parsing."""
        # Format: READ:WRITE (read_addr-count:write_addr=val1,val2)
        scanner_args["atomic-rw"] = "0-3:10=100,200,300"
        scanner = create_mock_scanner(scanner_args)

        arg = scanner.args.get("atomic-rw")
        read_part, write_part = arg.split(":")
        read_addr, read_count = map(int, read_part.split("-"))
        write_addr_str, write_values_str = write_part.split("=")
        write_addr = int(write_addr_str)
        write_values = [int(v) for v in write_values_str.split(",")]

        assert read_addr == 0
        assert read_count == 3
        assert write_addr == 10
        assert write_values == [100, 200, 300]

    def test_fifo_argument(self, scanner_args):
        """Test --fifo argument."""
        scanner_args["fifo"] = 100
        scanner = create_mock_scanner(scanner_args)

        fifo_addr = scanner.args.get("fifo")
        assert fifo_addr == 100


# =============================================================================
# Test Function Code Support Detection
# =============================================================================


class TestFunctionCodeSupportDetection:
    """Tests for detecting supported function codes."""

    def test_fc20_supported(self, mock_client, scanner_args):
        """Test detecting FC 20 support."""
        create_mock_scanner(scanner_args)

        result = mock_client.read_file_record([(1, 0, 1)], device_id=1)
        fc20_supported = not result.isError()

        assert fc20_supported is True

    def test_fc20_not_supported(self, mock_client, scanner_args):
        """Test detecting FC 20 not supported."""
        error_response = MagicMock()
        error_response.isError.return_value = True
        error_response.exception_code = 1
        mock_client.read_file_record.return_value = error_response

        create_mock_scanner(scanner_args)

        result = mock_client.read_file_record([(1, 0, 1)], device_id=1)
        fc20_supported = not result.isError()

        assert fc20_supported is False

    def test_fc22_supported(self, mock_client, scanner_args):
        """Test detecting FC 22 support."""
        create_mock_scanner(scanner_args)

        result = mock_client.mask_write_register(
            address=0, and_mask=0xFFFF, or_mask=0x0000, device_id=1
        )
        fc22_supported = not result.isError()

        assert fc22_supported is True

    def test_fc24_supported(self, mock_client, scanner_args):
        """Test detecting FC 24 support."""
        create_mock_scanner(scanner_args)

        result = mock_client.read_fifo_queue(address=0, device_id=1)
        fc24_supported = not result.isError()

        assert fc24_supported is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
