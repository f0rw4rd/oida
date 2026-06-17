"""
Shared fixtures for BACnet test suite.

Provides mock BACnet instances for mixin testing without network connections.
"""

import argparse
from unittest.mock import Mock


def create_mock_args(**overrides):
    """Create a mock args namespace with BACnet defaults."""
    defaults = {
        "who_is": False,
        "identify": False,
        "services": False,
        "enumerate_objects": False,
        "enumerate_properties": False,
        "present_value": False,
        "read": None,
        "write": None,
        "dump": False,
        "diff": None,
        "monitor": False,
        "assess": False,
        "assess_network": False,
        "assess_access": False,
        "assess_config": False,
        "assess_info": False,
        "check_anonymous": False,
        "check_schedules": False,
        "check_calendars": False,
        "check_alarms": False,
        "check_trendlogs": False,
        "check_priority": False,
        "check_bacnet_sc": False,
        "check_reinit": False,
        "check_oos": False,
        "check_life_safety": False,
        "enum_life_safety": False,
        "enum_bbmd": False,
        "enum_fdt": False,
        "enum_routers": False,
        "enum_networks": False,
        "enumerate_writable": False,
        "test_write": False,
        "test_dcc": False,
        "test_reinit_pass": False,
        "test_priority_writes": False,
        "test_time_sync": False,
        "test_oos": False,
        "test_bbmd_injection": False,
        "brute_force": False,
        "rpm": False,
        "read_range": False,
        "cov": False,
        "deep_enum": False,
        "enum_programs": False,
        "enum_loops": False,
        "vendor_scan": False,
        "discover_mstp": False,
        "networks": False,
        "scan_network": None,
        "scan_all_networks": False,
        "who_has": None,
        "files": False,
        "read_file": None,
        "quick": False,
        "discover": False,
        "full": False,
        "safe": False,
        "confirm": False,
        "port": 47808,
        "timeout": 3.0,
        "interface": None,
        "bbmd": None,
        "device_id": None,
        "device_range": None,
        "object_type": None,
        "max_objects": 1000,
        "object_types": None,
        "control_points": False,
        "values_only": False,
        "full_properties": False,
        "output": None,
        "format": "json",
        "interval": 1.0,
        "priority": None,
        "quiet": True,
        "debug": False,
        "verbose": 0,
        "password": None,
        "password_list": None,
        "retries": 1,
        "vendor_info": False,
        "rpm_batch_size": 10,
        "cov_lifetime": 300,
        "cov_duration": 30,
        "read_range_count": 50,
        "file_access_method": "stream",
        "file_chunk_size": 1024,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def create_mock_logger():
    """Create a mock logger with all required methods."""
    logger = Mock()
    logger.display = Mock()
    logger.success = Mock()
    logger.warning = Mock()
    logger.fail = Mock()
    logger.debug = Mock()
    logger.vuln = Mock()
    return logger
