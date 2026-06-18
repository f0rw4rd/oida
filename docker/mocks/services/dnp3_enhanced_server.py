#!/usr/bin/env python3
"""
Enhanced DNP3 Mock Outstation using pydnp3-stepfunc (stepfunc/dnp3 Rust library)

A feature-rich DNP3 outstation for testing the OIDA DNP3 scanner.
Implements proper handlers for:
- Freeze operations (immediate, clear, at-time)
- Cold/warm restart with configurable delays
- Dead band configuration (Group 34)
- Counter freeze tracking

LIMITATIONS (due to underlying stepfunc DNP3 library):
- File transfer operations (Group 70) - NOT SUPPORTED
  The stepfunc library does not expose outstation-side file handlers
- Application control (stop/start/init) - NOT SUPPORTED
- Delay measurement - Handled at protocol level, no custom handler needed
- Save configuration - NOT SUPPORTED

Environment Variables (in addition to basic server):
    DNP3_PORT              - Bind port (default: 20000)
    DNP3_OUTSTATION_ADDR   - Outstation address (default: "10")
    DNP3_MASTER_ADDR       - Expected master address (default: 1)
    DNP3_BI_COUNT          - Binary input count (default: 10)
    DNP3_AI_COUNT          - Analog input count (default: 10)
    DNP3_CT_COUNT          - Counter count (default: 5)
    DNP3_BO_COUNT          - Binary output count (default: 5)
    DNP3_AO_COUNT          - Analog output count (default: 5)
    DNP3_UPDATE_INTERVAL   - Value update interval in seconds (default: 5)
    DNP3_LOG_LEVEL         - Logging level: DEBUG, INFO, WARN, ERROR (default: INFO)
    DNP3_DEVICE_NAME       - Device name for attributes (default: "OIDA Enhanced Outstation")
    DNP3_SERIAL            - Device serial number (default: "OIDA-DNP3-ENH-001")
    DNP3_SOFTWARE_VERSION  - Software version attribute (default: "1.0.0")
    DNP3_HARDWARE_VERSION  - Hardware version attribute (default: "Rev-A")
    DNP3_TLS               - Enable TLS mode (default: false)
    DNP3_TLS_DNS_NAME      - DNS name for TLS certificates (default: "localhost")
    DNP3_COLD_RESTART_DELAY - Cold restart delay in seconds (default: 60)
    DNP3_WARM_RESTART_DELAY - Warm restart delay in milliseconds (default: 5000)
    DNP3_FROZEN_COUNTER_COUNT - Number of frozen counter points (default: CT_COUNT)
    DNP3_OCTET_COUNT       - Number of octet string points, Group 110 (default: 3)
"""

import datetime
import ipaddress
import logging
import math
import os
import pathlib
import signal
import sys
import time as _time
from typing import Dict

from dnp3 import Runtime
from dnp3._ffi import ffi, lib
from dnp3.outstation import (
    OutstationServer,
    OutstationConfig,
    EventBufferConfig,
    OutstationInformation,
    EventClass,
    Database,
)
from dnp3.handler import ConnectionStateListener
from dnp3.logging import configure_logging, LogLevel

# TLS support -- conditionally imported
try:
    from dnp3.outstation import TlsServerConfig, CertificateMode, MinTlsVersion

    _tls_available = True
except ImportError:
    _tls_available = False


# ---------------------------------------------------------------------------
# TLS certificate generation (copied from base server)
# ---------------------------------------------------------------------------


def generate_self_signed_certs(cert_dir: str, dns_name: str = "localhost"):
    """Generate a self-signed CA, server cert, and client cert for TLS testing."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    cert_path = pathlib.Path(cert_dir)
    cert_path.mkdir(parents=True, exist_ok=True)

    now = datetime.datetime.now(datetime.timezone.utc)
    one_year = datetime.timedelta(days=365)

    # --- CA ---
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "OIDA DNP3 Enhanced Mock CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OIDA Test"),
        ]
    )
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + one_year)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    # --- Server cert ---
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, dns_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OIDA Test"),
        ]
    )
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + one_year)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName(dns_name),
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                key_cert_sign=False,
                crl_sign=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    # --- Client cert ---
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, dns_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OIDA Test"),
        ]
    )
    client_cert = (
        x509.CertificateBuilder()
        .subject_name(client_name)
        .issuer_name(ca_name)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + one_year)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName(dns_name),
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                key_cert_sign=False,
                crl_sign=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    # Write all files
    no_enc = serialization.NoEncryption()

    def _write_key(path, key):
        path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                no_enc,
            )
        )

    def _write_cert(path, cert):
        path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    _write_cert(cert_path / "ca.pem", ca_cert)
    _write_key(cert_path / "ca-key.pem", ca_key)
    _write_cert(cert_path / "server.pem", server_cert)
    _write_key(cert_path / "server-key.pem", server_key)
    _write_cert(cert_path / "client.pem", client_cert)
    _write_key(cert_path / "client-key.pem", client_key)

    return {
        "ca_cert": str(cert_path / "ca.pem"),
        "ca_key": str(cert_path / "ca-key.pem"),
        "server_cert": str(cert_path / "server.pem"),
        "server_key": str(cert_path / "server-key.pem"),
        "client_cert": str(cert_path / "client.pem"),
        "client_key": str(cert_path / "client-key.pem"),
    }


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("dnp3-enhanced-outstation")


# ---------------------------------------------------------------------------
# Enhanced OutstationApplication with proper handlers
# ---------------------------------------------------------------------------


class EnhancedOutstationApplication:
    """
    Enhanced outstation application callbacks with full feature support.

    Implements:
    - Cold restart with configurable delay (returns SECONDS)
    - Warm restart with configurable delay (returns MILLISECONDS)
    - Freeze counters (all/range, immediate/clear/at-time)
    - Dead band configuration writes
    """

    def __init__(
        self,
        cold_restart_delay_sec: int = 60,
        warm_restart_delay_ms: int = 5000,
        ct_count: int = 5,
        ai_count: int = 10,
    ):
        self.cold_restart_delay = cold_restart_delay_sec
        self.warm_restart_delay = warm_restart_delay_ms
        self.ct_count = ct_count
        self.ai_count = ai_count

        # Track frozen counter values
        self.frozen_counters: Dict[int, int] = {}
        # Track dead band values
        self.dead_bands: Dict[int, float] = {i: 0.0 for i in range(ai_count)}

        # Current counter values (for freeze operations)
        self.counter_values: Dict[int, int] = {i: 0 for i in range(ct_count)}

        # --- Callbacks ---

        @ffi.callback("uint16_t(void*)")
        def _get_processing_delay_ms(ctx):
            # Return a non-zero processing delay to indicate the outstation
            # needs time to process. This affects delay measurement.
            return 10

        @ffi.callback("dnp3_write_time_result_t(uint64_t, void*)")
        def _write_absolute_time(time_ms, ctx):
            log.info(f"Time sync received: {time_ms} ms since epoch")
            return lib.DNP3_WRITE_TIME_RESULT_OK

        @ffi.callback("dnp3_application_iin_t(void*)")
        def _get_application_iin(ctx):
            return ffi.new(
                "dnp3_application_iin_t*",
                {
                    "need_time": False,
                    "local_control": False,
                    "device_trouble": False,
                    "config_corrupt": False,
                },
            )[0]

        @ffi.callback("dnp3_restart_delay_t(void*)")
        def _cold_restart(ctx):
            log.info(f"COLD RESTART requested - delay: {self.cold_restart_delay} seconds")
            return ffi.new(
                "dnp3_restart_delay_t*",
                {
                    "restart_type": lib.DNP3_RESTART_DELAY_TYPE_SECONDS,
                    "value": self.cold_restart_delay,
                },
            )[0]

        @ffi.callback("dnp3_restart_delay_t(void*)")
        def _warm_restart(ctx):
            log.info(f"WARM RESTART requested - delay: {self.warm_restart_delay} ms")
            return ffi.new(
                "dnp3_restart_delay_t*",
                {
                    "restart_type": lib.DNP3_RESTART_DELAY_TYPE_MILLI_SECONDS,
                    "value": self.warm_restart_delay,
                },
            )[0]

        @ffi.callback("dnp3_freeze_result_t(dnp3_freeze_type_t, dnp3_database_handle_t*, void*)")
        def _freeze_counters_all(freeze_type, db_handle, ctx):
            freeze_type_name = (
                "IMMEDIATE_FREEZE"
                if freeze_type == lib.DNP3_FREEZE_TYPE_IMMEDIATE_FREEZE
                else "FREEZE_AND_CLEAR"
            )
            log.info(f"FREEZE ALL counters: type={freeze_type_name}")

            # Perform the freeze operation on database
            try:

                def do_freeze(db):
                    for i in range(self.ct_count):
                        try:
                            counter = db.get_counter(i)
                            self.frozen_counters[i] = counter["value"]
                            # Update frozen counter point
                            db.update_frozen_counter(i, counter["value"], online=True)

                            if freeze_type == lib.DNP3_FREEZE_TYPE_FREEZE_AND_CLEAR:
                                # Clear the counter after freezing
                                db.update_counter(i, 0, online=True)
                                self.counter_values[i] = 0
                        except Exception as e:
                            log.warning(f"Failed to freeze counter {i}: {e}")

                Database.handle_transaction(db_handle, do_freeze)
                log.info(f"Frozen {len(self.frozen_counters)} counters")
                return lib.DNP3_FREEZE_RESULT_OK
            except Exception as e:
                log.error(f"Freeze all failed: {e}")
                return lib.DNP3_FREEZE_RESULT_NOT_SUPPORTED

        @ffi.callback("dnp3_freeze_result_t(dnp3_database_handle_t*, uint64_t, uint32_t, void*)")
        def _freeze_counters_all_at_time(db_handle, freeze_time_ms, interval_ms, ctx):
            log.info(
                f"FREEZE AT TIME (all counters): time={freeze_time_ms}ms, interval={interval_ms}ms"
            )

            try:

                def do_freeze(db):
                    for i in range(self.ct_count):
                        try:
                            counter = db.get_counter(i)
                            self.frozen_counters[i] = counter["value"]
                            db.update_frozen_counter(i, counter["value"], online=True)
                        except Exception as e:
                            log.warning(f"Failed to freeze counter {i}: {e}")

                Database.handle_transaction(db_handle, do_freeze)
                log.info(
                    f"Scheduled freeze for {len(self.frozen_counters)} counters at time {freeze_time_ms}"
                )
                return lib.DNP3_FREEZE_RESULT_OK
            except Exception as e:
                log.error(f"Freeze at time failed: {e}")
                return lib.DNP3_FREEZE_RESULT_NOT_SUPPORTED

        @ffi.callback(
            "dnp3_freeze_result_t(uint16_t, uint16_t, dnp3_freeze_type_t, dnp3_database_handle_t*, void*)"
        )
        def _freeze_counters_range(start, stop, freeze_type, db_handle, ctx):
            freeze_type_name = (
                "IMMEDIATE_FREEZE"
                if freeze_type == lib.DNP3_FREEZE_TYPE_IMMEDIATE_FREEZE
                else "FREEZE_AND_CLEAR"
            )
            log.info(f"FREEZE RANGE counters [{start}-{stop}]: type={freeze_type_name}")

            try:

                def do_freeze(db):
                    for i in range(start, min(stop + 1, self.ct_count)):
                        try:
                            counter = db.get_counter(i)
                            self.frozen_counters[i] = counter["value"]
                            db.update_frozen_counter(i, counter["value"], online=True)

                            if freeze_type == lib.DNP3_FREEZE_TYPE_FREEZE_AND_CLEAR:
                                db.update_counter(i, 0, online=True)
                                self.counter_values[i] = 0
                        except Exception as e:
                            log.warning(f"Failed to freeze counter {i}: {e}")

                Database.handle_transaction(db_handle, do_freeze)
                return lib.DNP3_FREEZE_RESULT_OK
            except Exception as e:
                log.error(f"Freeze range failed: {e}")
                return lib.DNP3_FREEZE_RESULT_NOT_SUPPORTED

        @ffi.callback(
            "dnp3_freeze_result_t(uint16_t, uint16_t, dnp3_database_handle_t*, uint64_t, uint32_t, void*)"
        )
        def _freeze_counters_range_at_time(
            start, stop, db_handle, freeze_time_ms, interval_ms, ctx
        ):
            log.info(
                f"FREEZE AT TIME (range [{start}-{stop}]): time={freeze_time_ms}ms, interval={interval_ms}ms"
            )

            try:

                def do_freeze(db):
                    for i in range(start, min(stop + 1, self.ct_count)):
                        try:
                            counter = db.get_counter(i)
                            self.frozen_counters[i] = counter["value"]
                            db.update_frozen_counter(i, counter["value"], online=True)
                        except Exception as e:
                            log.warning(f"Failed to freeze counter {i}: {e}")

                Database.handle_transaction(db_handle, do_freeze)
                return lib.DNP3_FREEZE_RESULT_OK
            except Exception as e:
                log.error(f"Freeze range at time failed: {e}")
                return lib.DNP3_FREEZE_RESULT_NOT_SUPPORTED

        # --- Dead band handlers ---

        @ffi.callback("_Bool(void*)")
        def _support_write_analog_dead_bands(ctx):
            log.debug("Dead band write support check: TRUE")
            return True

        @ffi.callback("void(void*)")
        def _begin_write_analog_dead_bands(ctx):
            log.info("BEGIN analog dead band write transaction")

        @ffi.callback("void(uint16_t, double, void*)")
        def _write_analog_dead_band(index, value, ctx):
            log.info(f"WRITE DEAD BAND: index={index}, value={value}")
            if index < self.ai_count:
                self.dead_bands[index] = value

        @ffi.callback("void(void*)")
        def _end_write_analog_dead_bands(ctx):
            log.info(
                f"END analog dead band write transaction. Current dead bands: {self.dead_bands}"
            )

        # --- String attribute write ---

        @ffi.callback("bool(uint8_t, uint8_t, dnp3_string_attr_t, const char*, void*)")
        def _write_string_attr(set_id, var, attr, value, ctx):
            value_str = ffi.string(value).decode() if value != ffi.NULL else ""
            log.info(f"WRITE STRING ATTR: set={set_id}, var={var}, value='{value_str}'")
            return True

        # --- Confirm handlers (for event acknowledgment tracking) ---

        @ffi.callback("void(void*)")
        def _begin_confirm(ctx):
            log.debug("Begin confirm")

        @ffi.callback("void(uint64_t, void*)")
        def _event_cleared(id, ctx):
            log.debug(f"Event {id} cleared")

        @ffi.callback("void(dnp3_buffer_state_t, void*)")
        def _end_confirm(buffer_state, ctx):
            log.debug("End confirm")

        # Store callbacks to prevent garbage collection
        self._get_processing_delay_ms = _get_processing_delay_ms
        self._write_absolute_time = _write_absolute_time
        self._get_application_iin = _get_application_iin
        self._cold_restart = _cold_restart
        self._warm_restart = _warm_restart
        self._freeze_counters_all = _freeze_counters_all
        self._freeze_counters_all_at_time = _freeze_counters_all_at_time
        self._freeze_counters_range = _freeze_counters_range
        self._freeze_counters_range_at_time = _freeze_counters_range_at_time
        self._support_write_analog_dead_bands = _support_write_analog_dead_bands
        self._begin_write_analog_dead_bands = _begin_write_analog_dead_bands
        self._write_analog_dead_band = _write_analog_dead_band
        self._end_write_analog_dead_bands = _end_write_analog_dead_bands
        self._write_string_attr = _write_string_attr
        self._begin_confirm = _begin_confirm
        self._event_cleared = _event_cleared
        self._end_confirm = _end_confirm

    def as_ffi(self):
        return ffi.new(
            "dnp3_outstation_application_t*",
            {
                "get_processing_delay_ms": self._get_processing_delay_ms,
                "write_absolute_time": self._write_absolute_time,
                "get_application_iin": self._get_application_iin,
                "cold_restart": self._cold_restart,
                "warm_restart": self._warm_restart,
                "freeze_counters_all": self._freeze_counters_all,
                "freeze_counters_all_at_time": self._freeze_counters_all_at_time,
                "freeze_counters_range": self._freeze_counters_range,
                "freeze_counters_range_at_time": self._freeze_counters_range_at_time,
                "support_write_analog_dead_bands": self._support_write_analog_dead_bands,
                "begin_write_analog_dead_bands": self._begin_write_analog_dead_bands,
                "write_analog_dead_band": self._write_analog_dead_band,
                "end_write_analog_dead_bands": self._end_write_analog_dead_bands,
                "write_string_attr": self._write_string_attr,
                "write_float_attr": ffi.NULL,
                "write_double_attr": ffi.NULL,
                "write_uint_attr": ffi.NULL,
                "write_int_attr": ffi.NULL,
                "write_octet_string_attr": ffi.NULL,
                "write_bit_string_attr": ffi.NULL,
                "write_time_attr": ffi.NULL,
                "begin_confirm": self._begin_confirm,
                "event_cleared": self._event_cleared,
                "end_confirm": self._end_confirm,
                "on_destroy": ffi.NULL,
                "ctx": ffi.NULL,
            },
        )[0]


# ---------------------------------------------------------------------------
# Enhanced Control Handler (accepts all controls with logging)
# ---------------------------------------------------------------------------


class EnhancedControlHandler:
    """Enhanced control handler that accepts controls and logs them."""

    def __init__(self, bo_count: int = 5, ao_count: int = 5):
        self.bo_count = bo_count
        self.ao_count = ao_count

        # Track control states
        self.binary_outputs: Dict[int, bool] = {i: False for i in range(bo_count)}
        self.analog_outputs: Dict[int, float] = {i: 0.0 for i in range(ao_count)}

        @ffi.callback("void(void*)")
        def _begin_fragment(ctx):
            log.debug("Control fragment begin")

        @ffi.callback("void(dnp3_database_handle_t*, void*)")
        def _end_fragment(db, ctx):
            log.debug("Control fragment end")

        @ffi.callback(
            "dnp3_command_status_t(dnp3_group12_var1_t, uint16_t, dnp3_database_handle_t*, void*)"
        )
        def _select_g12v1(control, index, db, ctx):
            log.info(f"SELECT binary output: index={index}")
            if index < self.bo_count:
                return lib.DNP3_COMMAND_STATUS_SUCCESS
            return lib.DNP3_COMMAND_STATUS_NOT_SUPPORTED

        @ffi.callback(
            "dnp3_command_status_t(dnp3_group12_var1_t, uint16_t, dnp3_operate_type_t, dnp3_database_handle_t*, void*)"
        )
        def _operate_g12v1(control, index, op_type, db_handle, ctx):
            log.info(f"OPERATE binary output: index={index}, op_type={op_type}")
            if index < self.bo_count:
                # Update the binary output state
                try:
                    new_value = True  # CROB typically sets to ON
                    self.binary_outputs[index] = new_value

                    def update_bo(db):
                        db.update_binary_output_status(index, new_value, online=True)

                    Database.handle_transaction(db_handle, update_bo)
                except Exception as e:
                    log.warning(f"Failed to update BO status: {e}")
                return lib.DNP3_COMMAND_STATUS_SUCCESS
            return lib.DNP3_COMMAND_STATUS_NOT_SUPPORTED

        # Analog output handlers (Group 41)

        @ffi.callback("dnp3_command_status_t(int32_t, uint16_t, dnp3_database_handle_t*, void*)")
        def _select_g41v1(value, index, db, ctx):
            log.info(f"SELECT analog output (int32): index={index}, value={value}")
            if index < self.ao_count:
                return lib.DNP3_COMMAND_STATUS_SUCCESS
            return lib.DNP3_COMMAND_STATUS_NOT_SUPPORTED

        @ffi.callback(
            "dnp3_command_status_t(int32_t, uint16_t, dnp3_operate_type_t, dnp3_database_handle_t*, void*)"
        )
        def _operate_g41v1(value, index, op_type, db_handle, ctx):
            log.info(f"OPERATE analog output (int32): index={index}, value={value}")
            if index < self.ao_count:
                self.analog_outputs[index] = float(value)
                try:

                    def update_ao(db):
                        db.update_analog_output_status(index, float(value), online=True)

                    Database.handle_transaction(db_handle, update_ao)
                except Exception as e:
                    log.warning(f"Failed to update AO status: {e}")
                return lib.DNP3_COMMAND_STATUS_SUCCESS
            return lib.DNP3_COMMAND_STATUS_NOT_SUPPORTED

        @ffi.callback("dnp3_command_status_t(int16_t, uint16_t, dnp3_database_handle_t*, void*)")
        def _select_g41v2(value, index, db, ctx):
            log.info(f"SELECT analog output (int16): index={index}, value={value}")
            if index < self.ao_count:
                return lib.DNP3_COMMAND_STATUS_SUCCESS
            return lib.DNP3_COMMAND_STATUS_NOT_SUPPORTED

        @ffi.callback(
            "dnp3_command_status_t(int16_t, uint16_t, dnp3_operate_type_t, dnp3_database_handle_t*, void*)"
        )
        def _operate_g41v2(value, index, op_type, db_handle, ctx):
            log.info(f"OPERATE analog output (int16): index={index}, value={value}")
            if index < self.ao_count:
                self.analog_outputs[index] = float(value)
                try:

                    def update_ao(db):
                        db.update_analog_output_status(index, float(value), online=True)

                    Database.handle_transaction(db_handle, update_ao)
                except Exception as e:
                    log.warning(f"Failed to update AO status: {e}")
                return lib.DNP3_COMMAND_STATUS_SUCCESS
            return lib.DNP3_COMMAND_STATUS_NOT_SUPPORTED

        @ffi.callback("dnp3_command_status_t(float, uint16_t, dnp3_database_handle_t*, void*)")
        def _select_g41v3(value, index, db, ctx):
            log.info(f"SELECT analog output (float): index={index}, value={value}")
            if index < self.ao_count:
                return lib.DNP3_COMMAND_STATUS_SUCCESS
            return lib.DNP3_COMMAND_STATUS_NOT_SUPPORTED

        @ffi.callback(
            "dnp3_command_status_t(float, uint16_t, dnp3_operate_type_t, dnp3_database_handle_t*, void*)"
        )
        def _operate_g41v3(value, index, op_type, db_handle, ctx):
            log.info(f"OPERATE analog output (float): index={index}, value={value}")
            if index < self.ao_count:
                self.analog_outputs[index] = float(value)
                try:

                    def update_ao(db):
                        db.update_analog_output_status(index, float(value), online=True)

                    Database.handle_transaction(db_handle, update_ao)
                except Exception as e:
                    log.warning(f"Failed to update AO status: {e}")
                return lib.DNP3_COMMAND_STATUS_SUCCESS
            return lib.DNP3_COMMAND_STATUS_NOT_SUPPORTED

        @ffi.callback("dnp3_command_status_t(double, uint16_t, dnp3_database_handle_t*, void*)")
        def _select_g41v4(value, index, db, ctx):
            log.info(f"SELECT analog output (double): index={index}, value={value}")
            if index < self.ao_count:
                return lib.DNP3_COMMAND_STATUS_SUCCESS
            return lib.DNP3_COMMAND_STATUS_NOT_SUPPORTED

        @ffi.callback(
            "dnp3_command_status_t(double, uint16_t, dnp3_operate_type_t, dnp3_database_handle_t*, void*)"
        )
        def _operate_g41v4(value, index, op_type, db_handle, ctx):
            log.info(f"OPERATE analog output (double): index={index}, value={value}")
            if index < self.ao_count:
                self.analog_outputs[index] = float(value)
                try:

                    def update_ao(db):
                        db.update_analog_output_status(index, float(value), online=True)

                    Database.handle_transaction(db_handle, update_ao)
                except Exception as e:
                    log.warning(f"Failed to update AO status: {e}")
                return lib.DNP3_COMMAND_STATUS_SUCCESS
            return lib.DNP3_COMMAND_STATUS_NOT_SUPPORTED

        self._begin_fragment = _begin_fragment
        self._end_fragment = _end_fragment
        self._select_g12v1 = _select_g12v1
        self._operate_g12v1 = _operate_g12v1
        self._select_g41v1 = _select_g41v1
        self._operate_g41v1 = _operate_g41v1
        self._select_g41v2 = _select_g41v2
        self._operate_g41v2 = _operate_g41v2
        self._select_g41v3 = _select_g41v3
        self._operate_g41v3 = _operate_g41v3
        self._select_g41v4 = _select_g41v4
        self._operate_g41v4 = _operate_g41v4

    def as_ffi(self):
        return ffi.new(
            "dnp3_control_handler_t*",
            {
                "begin_fragment": self._begin_fragment,
                "end_fragment": self._end_fragment,
                "select_g12v1": self._select_g12v1,
                "operate_g12v1": self._operate_g12v1,
                "select_g41v1": self._select_g41v1,
                "operate_g41v1": self._operate_g41v1,
                "select_g41v2": self._select_g41v2,
                "operate_g41v2": self._operate_g41v2,
                "select_g41v3": self._select_g41v3,
                "operate_g41v3": self._operate_g41v3,
                "select_g41v4": self._select_g41v4,
                "operate_g41v4": self._operate_g41v4,
                "on_destroy": ffi.NULL,
                "ctx": ffi.NULL,
            },
        )[0]


# ---------------------------------------------------------------------------
# Database initialization
# ---------------------------------------------------------------------------


def init_database(outstation, cfg, app: EnhancedOutstationApplication):
    """Populate the outstation database with test data points and attributes."""

    def _init_db(db):
        # Binary inputs
        for i in range(cfg["bi_count"]):
            db.add_binary_input(
                i,
                EventClass.CLASS1,
                static_variation=lib.DNP3_STATIC_BINARY_INPUT_VARIATION_GROUP1_VAR2,
                event_variation=lib.DNP3_EVENT_BINARY_INPUT_VARIATION_GROUP2_VAR2,
            )

        # Analog inputs
        for i in range(cfg["ai_count"]):
            db.add_analog_input(
                i,
                EventClass.CLASS1,
                static_variation=lib.DNP3_STATIC_ANALOG_INPUT_VARIATION_GROUP30_VAR5,
                event_variation=lib.DNP3_EVENT_ANALOG_INPUT_VARIATION_GROUP32_VAR5,
                deadband=app.dead_bands.get(i, 0.0),
            )

        # Counters
        for i in range(cfg["ct_count"]):
            db.add_counter(
                i,
                EventClass.CLASS1,
                static_variation=lib.DNP3_STATIC_COUNTER_VARIATION_GROUP20_VAR1,
                event_variation=lib.DNP3_EVENT_COUNTER_VARIATION_GROUP22_VAR1,
                deadband=0,
            )

        # Frozen counters
        for i in range(cfg["frozen_ct_count"]):
            db.add_frozen_counter(
                i,
                EventClass.CLASS1,
                static_variation=lib.DNP3_STATIC_FROZEN_COUNTER_VARIATION_GROUP21_VAR1,
                event_variation=lib.DNP3_EVENT_FROZEN_COUNTER_VARIATION_GROUP23_VAR1,
                deadband=0,
            )

        # Binary output status
        for i in range(cfg["bo_count"]):
            db.add_binary_output_status(
                i,
                EventClass.CLASS1,
                static_variation=lib.DNP3_STATIC_BINARY_OUTPUT_STATUS_VARIATION_GROUP10_VAR2,
                event_variation=lib.DNP3_EVENT_BINARY_OUTPUT_STATUS_VARIATION_GROUP11_VAR2,
            )

        # Analog output status
        for i in range(cfg["ao_count"]):
            db.add_analog_output_status(
                i,
                EventClass.CLASS1,
                static_variation=lib.DNP3_STATIC_ANALOG_OUTPUT_STATUS_VARIATION_GROUP40_VAR3,
                event_variation=lib.DNP3_EVENT_ANALOG_OUTPUT_STATUS_VARIATION_GROUP42_VAR5,
                deadband=0.0,
            )

        # Device attributes
        db.define_string_attr(
            0,
            False,
            lib.DNP3_ATTRIBUTE_VARIATIONS_DEVICE_MANUFACTURERS_NAME,
            "OIDA Mock",
        )
        db.define_string_attr(
            0,
            False,
            lib.DNP3_ATTRIBUTE_VARIATIONS_PRODUCT_NAME_AND_MODEL,
            cfg["device_name"],
        )
        db.define_string_attr(
            0,
            False,
            lib.DNP3_ATTRIBUTE_VARIATIONS_DEVICE_SERIAL_NUMBER,
            cfg["serial_number"],
        )
        db.define_string_attr(
            0,
            True,
            lib.DNP3_ATTRIBUTE_VARIATIONS_USER_ASSIGNED_LOCATION,
            f"Outstation {cfg['outstation_addr']} - OIDA Enhanced Test",
        )
        db.define_string_attr(
            0,
            False,
            lib.DNP3_ATTRIBUTE_VARIATIONS_DEVICE_MANUFACTURER_SOFTWARE_VERSION,
            cfg["software_version"],
        )
        db.define_string_attr(
            0,
            False,
            lib.DNP3_ATTRIBUTE_VARIATIONS_DEVICE_MANUFACTURER_HARDWARE_VERSION,
            cfg["hardware_version"],
        )

        # Octet strings (Group 110)
        for i in range(cfg.get("octet_count", 3)):
            db.add_octet_string(i, EventClass.CLASS1)

        # Define numeric attributes for point counts
        db.define_uint_attr(
            0, False, lib.DNP3_ATTRIBUTE_VARIATIONS_NUM_BINARY_INPUT, cfg["bi_count"]
        )
        db.define_uint_attr(
            0, False, lib.DNP3_ATTRIBUTE_VARIATIONS_NUM_ANALOG_INPUT, cfg["ai_count"]
        )
        db.define_uint_attr(0, False, lib.DNP3_ATTRIBUTE_VARIATIONS_NUM_COUNTER, cfg["ct_count"])
        db.define_uint_attr(
            0, False, lib.DNP3_ATTRIBUTE_VARIATIONS_NUM_BINARY_OUTPUTS, cfg["bo_count"]
        )
        db.define_uint_attr(
            0, False, lib.DNP3_ATTRIBUTE_VARIATIONS_NUM_ANALOG_OUTPUTS, cfg["ao_count"]
        )

    outstation.transaction(_init_db)

    # Populate initial octet string values
    def _init_octet(db):
        octet_labels = ["firmware-hash", "config-rev", "vendor-blob"]
        for i in range(cfg.get("octet_count", 3)):
            label = octet_labels[i] if i < len(octet_labels) else f"octet-{i}"
            db.update_octet_string(i, label.encode("utf-8"))

    outstation.transaction(_init_octet)


# ---------------------------------------------------------------------------
# Periodic value updates
# ---------------------------------------------------------------------------


def update_values(outstation, cfg, cycle, app: EnhancedOutstationApplication):
    """Update data point values to simulate a live outstation."""

    def _update(db):
        # Binary inputs -- toggle every few cycles
        for i in range(cfg["bi_count"]):
            val = ((cycle + i) % 4) < 2
            db.update_binary_input(i, val, online=True)

        # Analog inputs -- sine wave
        for i in range(cfg["ai_count"]):
            val = 100.0 + i * 10.0 + 5.0 * math.sin(cycle * 0.1 + i)
            db.update_analog_input(i, val, online=True)

        # Counters -- incrementing
        for i in range(cfg["ct_count"]):
            val = cycle * (i + 1)
            app.counter_values[i] = val
            db.update_counter(i, val, online=True)

    outstation.transaction(_update)


# ---------------------------------------------------------------------------
# Configuration parsing
# ---------------------------------------------------------------------------

LOG_LEVEL_MAP = {
    "DEBUG": LogLevel.DEBUG,
    "INFO": LogLevel.INFO,
    "WARN": LogLevel.WARN,
    "WARNING": LogLevel.WARN,
    "ERROR": LogLevel.ERROR,
}


def parse_config():
    """Parse configuration from environment variables."""
    port = int(os.environ.get("DNP3_PORT", "20000"))
    outstation_addr = int(os.environ.get("DNP3_OUTSTATION_ADDR", "10"))
    master_addr = int(os.environ.get("DNP3_MASTER_ADDR", "1"))
    bi_count = int(os.environ.get("DNP3_BI_COUNT", "10"))
    ai_count = int(os.environ.get("DNP3_AI_COUNT", "10"))
    ct_count = int(os.environ.get("DNP3_CT_COUNT", "5"))
    bo_count = int(os.environ.get("DNP3_BO_COUNT", "5"))
    ao_count = int(os.environ.get("DNP3_AO_COUNT", "5"))
    frozen_ct_count = int(os.environ.get("DNP3_FROZEN_COUNTER_COUNT", str(ct_count)))
    octet_count = int(os.environ.get("DNP3_OCTET_COUNT", "3"))
    update_interval = float(os.environ.get("DNP3_UPDATE_INTERVAL", "5"))
    log_level_str = os.environ.get("DNP3_LOG_LEVEL", "INFO").upper()
    log_level = LOG_LEVEL_MAP.get(log_level_str, LogLevel.INFO)
    device_name = os.environ.get("DNP3_DEVICE_NAME", "OIDA Enhanced Outstation")
    serial_number = os.environ.get("DNP3_SERIAL", "OIDA-DNP3-ENH-001")
    software_version = os.environ.get("DNP3_SOFTWARE_VERSION", "1.0.0")
    hardware_version = os.environ.get("DNP3_HARDWARE_VERSION", "Rev-A")

    # Restart delays
    cold_restart_delay = int(os.environ.get("DNP3_COLD_RESTART_DELAY", "60"))
    warm_restart_delay = int(os.environ.get("DNP3_WARM_RESTART_DELAY", "5000"))

    # TLS configuration
    tls_enabled = os.environ.get("DNP3_TLS", "false").lower() in ("true", "1", "yes")
    tls_dns_name = os.environ.get("DNP3_TLS_DNS_NAME", "localhost")

    return {
        "port": port,
        "outstation_addr": outstation_addr,
        "master_addr": master_addr,
        "bi_count": bi_count,
        "ai_count": ai_count,
        "ct_count": ct_count,
        "bo_count": bo_count,
        "ao_count": ao_count,
        "frozen_ct_count": frozen_ct_count,
        "octet_count": octet_count,
        "update_interval": update_interval,
        "log_level": log_level,
        "device_name": device_name,
        "serial_number": serial_number,
        "software_version": software_version,
        "hardware_version": hardware_version,
        "cold_restart_delay": cold_restart_delay,
        "warm_restart_delay": warm_restart_delay,
        "tls_enabled": tls_enabled,
        "tls_dns_name": tls_dns_name,
    }


# ---------------------------------------------------------------------------
# Server setup helpers
# ---------------------------------------------------------------------------

_outstation_refs = []


def add_outstation_to_server(server, cfg):
    """Add enhanced outstation to server with all feature handlers."""

    app = EnhancedOutstationApplication(
        cold_restart_delay_sec=cfg["cold_restart_delay"],
        warm_restart_delay_ms=cfg["warm_restart_delay"],
        ct_count=cfg["ct_count"],
        ai_count=cfg["ai_count"],
    )
    info = OutstationInformation()
    ctrl = EnhancedControlHandler(
        bo_count=cfg["bo_count"],
        ao_count=cfg["ao_count"],
    )
    listener = ConnectionStateListener()

    config = OutstationConfig(
        outstation_address=cfg["outstation_addr"],
        master_address=cfg["master_addr"],
        event_buffer=EventBufferConfig(
            binary=max(50, cfg["bi_count"] * 2),
            double_bit_binary=10,
            binary_output_status=max(10, cfg["bo_count"] * 2),
            counter=max(20, cfg["ct_count"] * 2),
            frozen_counter=max(10, cfg["frozen_ct_count"] * 2),
            analog=max(50, cfg["ai_count"] * 2),
            analog_output_status=max(10, cfg["ao_count"] * 2),
        ),
    )

    # Create FFI structs
    config_ffi = config.to_ffi()
    app_ffi = app.as_ffi()
    info_ffi = info.as_ffi()
    ctrl_ffi = ctrl.as_ffi()
    listener_ffi = listener.as_ffi()

    # Get address filter (any)
    af = lib.dnp3_address_filter_any()

    outstation_ptr = ffi.new("dnp3_outstation_t**")
    err = lib.dnp3_outstation_server_add_outstation(
        server._ptr,
        config_ffi,
        app_ffi,
        info_ffi,
        ctrl_ffi,
        listener_ffi,
        af,
        outstation_ptr,
    )
    lib.dnp3_address_filter_destroy(af)

    from dnp3._ffi import check_error

    check_error(err)

    # Create Outstation wrapper
    from dnp3.outstation import Outstation

    outstation = Outstation(
        outstation_ptr[0],
        _refs=[app, info, ctrl, listener],
    )

    # Keep references alive
    _outstation_refs.append((app, info, ctrl, listener))

    init_database(outstation, cfg, app)

    return outstation, app


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    cfg = parse_config()
    bind_addr = f"0.0.0.0:{cfg['port']}"

    configure_logging(cfg["log_level"])

    tls_enabled = cfg["tls_enabled"]
    tls_dns_name = cfg["tls_dns_name"]

    log.info("=" * 70)
    log.info("DNP3 Enhanced Outstation Server (pydnp3-stepfunc)")
    log.info("=" * 70)
    log.info("  Bind address:        %s", bind_addr)
    log.info("  Outstation addr:     %d", cfg["outstation_addr"])
    log.info("  Master address:      %d", cfg["master_addr"])
    log.info(
        "  Points: %d BI, %d AI, %d CT, %d FCT, %d BO, %d AO",
        cfg["bi_count"],
        cfg["ai_count"],
        cfg["ct_count"],
        cfg["frozen_ct_count"],
        cfg["bo_count"],
        cfg["ao_count"],
    )
    log.info("  Update interval:     %.1f s", cfg["update_interval"])
    log.info("  Cold restart delay:  %d seconds", cfg["cold_restart_delay"])
    log.info("  Warm restart delay:  %d ms", cfg["warm_restart_delay"])
    log.info("  Device name:         %s", cfg["device_name"])
    log.info("  Serial number:       %s", cfg["serial_number"])
    log.info("  TLS:                 %s", "enabled" if tls_enabled else "disabled")
    log.info("-" * 70)
    log.info("SUPPORTED FEATURES:")
    log.info("  - Cold/Warm restart:     YES (with configurable delays)")
    log.info("  - Freeze operations:     YES (immediate, clear, at-time)")
    log.info("  - Dead band writes:      YES (Group 34)")
    log.info("  - Time sync:             YES (write absolute time)")
    log.info("  - Control operations:    YES (CROB, analog output)")
    log.info("-" * 70)
    log.info("UNSUPPORTED FEATURES (library limitation):")
    log.info("  - File transfer (G70):   NO  (no outstation file handler in lib)")
    log.info("  - Application control:   NO  (stop/start/init not exposed)")
    log.info("  - Save configuration:    NO  (not in application callbacks)")
    log.info("  - Class assignment:      NO  (not in application callbacks)")
    log.info("=" * 70)
    sys.stdout.flush()

    # Generate TLS certificates if TLS mode is enabled
    tls_config = None
    if tls_enabled:
        if not _tls_available:
            log.error("TLS requested but TlsServerConfig not available. Falling back to TCP.")
            tls_enabled = False
        else:
            cert_dir = "/app/certs"
            log.info("Generating self-signed certificates in %s ...", cert_dir)
            try:
                cert_paths = generate_self_signed_certs(cert_dir, dns_name=tls_dns_name)
                log.info("  CA cert:     %s", cert_paths["ca_cert"])
                log.info("  Server cert: %s", cert_paths["server_cert"])

                tls_config = TlsServerConfig(
                    dns_name=tls_dns_name,
                    peer_cert_path=cert_paths["ca_cert"],
                    local_cert_path=cert_paths["server_cert"],
                    private_key_path=cert_paths["server_key"],
                    password="",
                    min_tls_version=MinTlsVersion.V12,
                    certificate_mode=CertificateMode.AUTHORITY_BASED,
                    allow_client_name_wildcard=True,
                )
            except Exception as exc:
                log.error("Failed to set up TLS: %s -- falling back to TCP", exc)
                tls_enabled = False
                tls_config = None

    with Runtime(num_threads=4) as runtime:
        if tls_config is not None:
            log.info("Creating TLS outstation server on %s", bind_addr)
            server = OutstationServer(runtime, address=bind_addr, tls_config=tls_config)
        else:
            server = OutstationServer(runtime, address=bind_addr)

        try:
            outstation, app = add_outstation_to_server(server, cfg)
            log.info("Added enhanced outstation addr=%d", cfg["outstation_addr"])
        except Exception as exc:
            log.error("Could not add outstation: %s", exc)
            sys.exit(1)

        server.bind()

        log.info("Server bound and accepting connections")
        sys.stdout.flush()

        running = True

        def signal_handler(sig, frame):
            nonlocal running
            running = False

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        cycle = 0
        try:
            while running:
                _time.sleep(cfg["update_interval"])
                cycle += 1
                update_values(outstation, cfg, cycle, app)
        except KeyboardInterrupt:
            pass

        log.info("Shutting down...")
        server.destroy()
        log.info("Server stopped")


if __name__ == "__main__":
    main()
