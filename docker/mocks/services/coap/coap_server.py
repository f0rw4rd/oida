#!/usr/bin/env python3
"""CoAP Mock Server for OIDA integration testing.

Full-featured CoAP device simulator using aiocoap. Provides standard IoT
resources, LwM2M device objects, observable sensors, writable actuators,
and intentional security misconfigurations for scanner validation.

Resources (auto-listed in /.well-known/core):
  /sensor/temperature   -- observable, sine-wave float, text/plain
  /sensor/humidity      -- observable, float, text/plain
  /sensor/pressure      -- observable, float, text/plain
  /sensor/large-data    -- GET, >2KB JSON array (block-wise transfer test)
  /sensor/data.cbor     -- GET, CBOR-encoded sensor data (ct=60)
  /sensor/measurements  -- GET, SenML JSON array (ct=110)
  /actuator/led         -- GET/PUT, "0"/"1"
  /actuator/relay       -- GET/PUT, "0"/"1" (writable without auth = security finding)
  /actuator/valve       -- GET/PUT, 0-100 percentage
  /config               -- GET/PUT/FETCH/PATCH/iPATCH, JSON config blob
  /firmware/version     -- GET only, returns "1.2.3"
  /time                 -- GET only, ISO timestamp
  /device               -- GET only, JSON device info
  /3/0.json             -- GET, LwM2M JSON format (ct=11543)

LwM2M paths:
  /3/0/0  -> "OIDA-Test"       (manufacturer)
  /3/0/1  -> "CoAP-Mock-v1"    (model)
  /3/0/2  -> "SN-2024-001337"  (serial)
  /3/0/3  -> "1.2.3-beta"      (firmware version)
  /3/0/9  -> "87"              (battery level)
  /3/0/13 -> current unix timestamp
  /0/0/2  -> "3"               (NoSec mode -- intentional security finding)
  /1/0/1  -> "3600"            (lifetime)
  /5/0/3  -> "0"               (firmware update state)

Behavior:
  - Observable resources push notifications every 2s
  - PUT to /actuator/* succeeds without auth (intentional)
  - DELETE returns 2.02 on actuator paths
  - All methods return proper CoAP response codes
  - Per-request logging with method, path, client address

Usage:
    python3 coap_server.py [--port PORT] [--verbose]
"""

import argparse
import asyncio
import logging
import math
import time
import json
from datetime import datetime, timezone

import aiocoap
import aiocoap.resource as resource

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Observable sensor resources
# ---------------------------------------------------------------------------


class TemperatureResource(resource.ObservableResource):
    """Observable temperature sensor -- sine wave between 18.0 and 28.0 degC."""

    def __init__(self):
        super().__init__()
        self._start = time.time()
        self.notify()

    def notify(self):
        self.updated_state()
        asyncio.get_event_loop().call_later(2.0, self.notify)

    def _value(self) -> float:
        elapsed = time.time() - self._start
        return round(23.0 + 5.0 * math.sin(elapsed / 30.0), 2)

    async def render_get(self, request):
        value = str(self._value())
        logger.info("GET /sensor/temperature -> %s (from %s)", value, request.remote.hostinfo)
        return aiocoap.Message(
            payload=value.encode("utf-8"),
            content_format=0,  # text/plain
        )


class HumidityResource(resource.ObservableResource):
    """Observable humidity sensor -- slow drift around 55%."""

    def __init__(self):
        super().__init__()
        self._start = time.time()
        self.notify()

    def notify(self):
        self.updated_state()
        asyncio.get_event_loop().call_later(2.0, self.notify)

    def _value(self) -> float:
        elapsed = time.time() - self._start
        return round(55.0 + 8.0 * math.sin(elapsed / 45.0 + 1.0), 2)

    async def render_get(self, request):
        value = str(self._value())
        logger.info("GET /sensor/humidity -> %s (from %s)", value, request.remote.hostinfo)
        return aiocoap.Message(
            payload=value.encode("utf-8"),
            content_format=0,
        )


class PressureResource(resource.ObservableResource):
    """Observable pressure sensor -- around 1013 hPa."""

    def __init__(self):
        super().__init__()
        self._start = time.time()
        self.notify()

    def notify(self):
        self.updated_state()
        asyncio.get_event_loop().call_later(2.0, self.notify)

    def _value(self) -> float:
        elapsed = time.time() - self._start
        return round(1013.25 + 2.0 * math.sin(elapsed / 60.0 + 2.0), 2)

    async def render_get(self, request):
        value = str(self._value())
        logger.info("GET /sensor/pressure -> %s (from %s)", value, request.remote.hostinfo)
        return aiocoap.Message(
            payload=value.encode("utf-8"),
            content_format=0,
        )


# ---------------------------------------------------------------------------
# Large resource for block-wise transfer testing (RFC 7959)
# ---------------------------------------------------------------------------


class LargeDataResource(resource.Resource):
    """Large resource to test Block2 block-wise transfer.

    Returns >2KB JSON array of 100 sensor readings. When the client
    requests with a small block size, this triggers Block2 negotiation.
    """

    async def render_get(self, request):
        readings = [
            {
                "id": i,
                "temperature": round(20.0 + (i % 10), 2),
                "humidity": round(50.0 + (i % 20), 2),
                "timestamp": f"2024-01-01T00:{i:02d}:00Z",
            }
            for i in range(100)
        ]
        payload = json.dumps(readings).encode("utf-8")
        logger.info(
            "GET /sensor/large-data -> %d bytes (%d readings) (from %s)",
            len(payload),
            len(readings),
            request.remote.hostinfo,
        )
        return aiocoap.Message(payload=payload, content_format=50)


# ---------------------------------------------------------------------------
# Content format resources (CBOR, SenML, LwM2M JSON)
# ---------------------------------------------------------------------------


class CborSensorResource(resource.Resource):
    """CBOR-encoded sensor data (content_format=60).

    Returns a CBOR map with temperature, humidity, and pressure.
    Uses cbor2 if available, otherwise returns a hardcoded CBOR blob.
    """

    async def render_get(self, request):
        data = {
            "temperature": 23.5,
            "humidity": 55.0,
            "pressure": 1013.25,
            "unit": "metric",
        }
        try:
            import cbor2

            payload = cbor2.dumps(data)
        except ImportError:
            # Hardcoded CBOR encoding of the above map
            # {temperature: 23.5, humidity: 55.0, pressure: 1013.25, unit: "metric"}
            payload = (
                b"\xa4"  # map(4)
                b"\x6b"
                b"temperature"  # text(11)
                b"\xfb\x40\x37\x80\x00\x00\x00\x00\x00"  # float64(23.5)
                b"\x68"
                b"humidity"  # text(8)
                b"\xfb\x40\x4b\x80\x00\x00\x00\x00\x00"  # float64(55.0)
                b"\x68"
                b"pressure"  # text(8)
                b"\xfb\x40\x8f\xca\x00\x00\x00\x00\x00"  # float64(1013.25)
                b"\x64"
                b"unit"  # text(4)
                b"\x66"
                b"metric"  # text(6)
            )
        logger.info(
            "GET /sensor/data.cbor -> %d bytes CBOR (from %s)",
            len(payload),
            request.remote.hostinfo,
        )
        return aiocoap.Message(payload=payload, content_format=60)


class SenMLResource(resource.Resource):
    """SenML JSON sensor measurements (content_format=110).

    Returns a SenML JSON array (RFC 8428) with sensor readings.
    """

    async def render_get(self, request):
        senml = [
            {"bn": "urn:dev:ow:10e2073a01080063:", "bt": int(time.time()), "ver": 1},
            {"n": "temperature", "u": "Cel", "v": 23.5},
            {"n": "humidity", "u": "%RH", "v": 55.0},
            {"n": "pressure", "u": "Pa", "v": 101325.0},
        ]
        payload = json.dumps(senml).encode("utf-8")
        logger.info(
            "GET /sensor/measurements -> %d bytes SenML (from %s)",
            len(payload),
            request.remote.hostinfo,
        )
        return aiocoap.Message(payload=payload, content_format=110)


class LwM2MJsonResource(resource.Resource):
    """LwM2M JSON device object (content_format=11543).

    Returns LwM2M JSON encoding of the /3/0 Device Object.
    """

    async def render_get(self, request):
        lwm2m_json = {
            "bn": "/3/0/",
            "e": [
                {"n": "0", "sv": "OIDA-Test"},
                {"n": "1", "sv": "CoAP-Mock-v1"},
                {"n": "2", "sv": "SN-2024-001337"},
                {"n": "3", "sv": "1.2.3-beta"},
                {"n": "9", "v": 87},
                {"n": "13", "v": int(time.time())},
            ],
        }
        payload = json.dumps(lwm2m_json).encode("utf-8")
        logger.info(
            "GET /3/0.json -> %d bytes LwM2M JSON (from %s)",
            len(payload),
            request.remote.hostinfo,
        )
        return aiocoap.Message(payload=payload, content_format=11543)


# ---------------------------------------------------------------------------
# Actuator resources (writable without auth -- intentional security finding)
# ---------------------------------------------------------------------------


class LedResource(resource.Resource):
    """LED actuator -- GET/PUT, accepts "0" or "1"."""

    def __init__(self):
        super().__init__()
        self._state = "0"

    async def render_get(self, request):
        logger.info("GET /actuator/led -> %s (from %s)", self._state, request.remote.hostinfo)
        return aiocoap.Message(
            payload=self._state.encode("utf-8"),
            content_format=0,
        )

    async def render_put(self, request):
        value = request.payload.decode("utf-8").strip()
        logger.info("PUT /actuator/led <- %s (from %s)", value, request.remote.hostinfo)
        if value in ("0", "1"):
            self._state = value
            return aiocoap.Message(code=aiocoap.CHANGED, payload=b"OK")
        return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=b"Expected 0 or 1")

    async def render_delete(self, request):
        logger.info("DELETE /actuator/led (from %s)", request.remote.hostinfo)
        self._state = "0"
        return aiocoap.Message(code=aiocoap.DELETED, payload=b"Reset")


class RelayResource(resource.Resource):
    """Relay actuator -- GET/PUT, accepts "0" or "1". Writable without auth."""

    def __init__(self):
        super().__init__()
        self._state = "0"

    async def render_get(self, request):
        logger.info("GET /actuator/relay -> %s (from %s)", self._state, request.remote.hostinfo)
        return aiocoap.Message(
            payload=self._state.encode("utf-8"),
            content_format=0,
        )

    async def render_put(self, request):
        value = request.payload.decode("utf-8").strip()
        logger.info("PUT /actuator/relay <- %s (from %s)", value, request.remote.hostinfo)
        if value in ("0", "1"):
            self._state = value
            return aiocoap.Message(code=aiocoap.CHANGED, payload=b"OK")
        return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=b"Expected 0 or 1")

    async def render_delete(self, request):
        logger.info("DELETE /actuator/relay (from %s)", request.remote.hostinfo)
        self._state = "0"
        return aiocoap.Message(code=aiocoap.DELETED, payload=b"Reset")


class ValveResource(resource.Resource):
    """Valve actuator -- GET/PUT, accepts 0-100 percentage."""

    def __init__(self):
        super().__init__()
        self._value = "50"

    async def render_get(self, request):
        logger.info("GET /actuator/valve -> %s (from %s)", self._value, request.remote.hostinfo)
        return aiocoap.Message(
            payload=self._value.encode("utf-8"),
            content_format=0,
        )

    async def render_put(self, request):
        raw = request.payload.decode("utf-8").strip()
        logger.info("PUT /actuator/valve <- %s (from %s)", raw, request.remote.hostinfo)
        try:
            val = int(raw)
            if 0 <= val <= 100:
                self._value = str(val)
                return aiocoap.Message(code=aiocoap.CHANGED, payload=b"OK")
            return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=b"Value must be 0-100")
        except ValueError:
            return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=b"Expected integer 0-100")

    async def render_delete(self, request):
        logger.info("DELETE /actuator/valve (from %s)", request.remote.hostinfo)
        self._value = "0"
        return aiocoap.Message(code=aiocoap.DELETED, payload=b"Reset")


# ---------------------------------------------------------------------------
# Configuration resource (GET/PUT JSON)
# ---------------------------------------------------------------------------


class ConfigResource(resource.Resource):
    """Device configuration -- GET/PUT/FETCH/PATCH/iPATCH JSON blob.

    FETCH (RFC 8132): Accept JSON with "fields" key, return filtered config.
    PATCH (RFC 8132): Merge JSON payload into config (partial update).
    iPATCH (RFC 8132): Same as PATCH (idempotent merge).
    """

    def __init__(self):
        super().__init__()
        self._config = {
            "device_name": "OIDA CoAP Mock",
            "reporting_interval": 30,
            "threshold_high": 28.0,
            "threshold_low": 18.0,
            "alarm_enabled": True,
            "firmware_auto_update": False,
        }

    async def render_get(self, request):
        payload = json.dumps(self._config, indent=2)
        logger.info("GET /config -> %d bytes (from %s)", len(payload), request.remote.hostinfo)
        return aiocoap.Message(
            payload=payload.encode("utf-8"),
            content_format=50,  # application/json
        )

    async def render_put(self, request):
        logger.info(
            "PUT /config <- %d bytes (from %s)", len(request.payload), request.remote.hostinfo
        )
        try:
            new_config = json.loads(request.payload.decode("utf-8"))
            self._config.update(new_config)
            return aiocoap.Message(code=aiocoap.CHANGED, payload=b"Config updated")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=b"Invalid JSON")

    async def render_fetch(self, request):
        """FETCH /config -- return filtered config based on "fields" in payload."""
        logger.info(
            "FETCH /config <- %d bytes (from %s)", len(request.payload), request.remote.hostinfo
        )
        try:
            body = json.loads(request.payload.decode("utf-8"))
            fields = body.get("fields", [])
            if fields:
                filtered = {k: v for k, v in self._config.items() if k in fields}
            else:
                filtered = self._config
            payload = json.dumps(filtered, indent=2).encode("utf-8")
            return aiocoap.Message(payload=payload, content_format=50)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=b"Invalid JSON")

    async def render_patch(self, request):
        """PATCH /config -- merge partial JSON update into config."""
        logger.info(
            "PATCH /config <- %d bytes (from %s)", len(request.payload), request.remote.hostinfo
        )
        try:
            patch_data = json.loads(request.payload.decode("utf-8"))
            self._config.update(patch_data)
            return aiocoap.Message(code=aiocoap.CHANGED, payload=b"Config patched")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=b"Invalid JSON")

    async def render_ipatch(self, request):
        """iPATCH /config -- idempotent merge (same as PATCH for JSON)."""
        logger.info(
            "iPATCH /config <- %d bytes (from %s)", len(request.payload), request.remote.hostinfo
        )
        try:
            patch_data = json.loads(request.payload.decode("utf-8"))
            self._config.update(patch_data)
            return aiocoap.Message(code=aiocoap.CHANGED, payload=b"Config ipatched")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=b"Invalid JSON")


# ---------------------------------------------------------------------------
# Read-only informational resources
# ---------------------------------------------------------------------------


class FirmwareVersionResource(resource.Resource):
    """Firmware version -- GET only, returns "1.2.3"."""

    async def render_get(self, request):
        logger.info("GET /firmware/version -> 1.2.3 (from %s)", request.remote.hostinfo)
        return aiocoap.Message(
            payload=b"1.2.3",
            content_format=0,
        )


class TimeResource(resource.Resource):
    """Current time -- GET only, ISO timestamp."""

    async def render_get(self, request):
        now = datetime.now(timezone.utc).isoformat()
        logger.info("GET /time -> %s (from %s)", now, request.remote.hostinfo)
        return aiocoap.Message(
            payload=now.encode("utf-8"),
            content_format=0,
        )


class DeviceResource(resource.Resource):
    """Device info -- GET only, JSON with device metadata."""

    async def render_get(self, request):
        info = {
            "manufacturer": "OIDA-Test",
            "model": "CoAP-Mock-v1",
            "serial": "SN-2024-001337",
            "firmware": "1.2.3-beta",
            "uptime_seconds": int(time.time()) % 86400,
            "protocol": "CoAP",
            "security": "NoSec",
        }
        payload = json.dumps(info, indent=2)
        logger.info("GET /device -> %d bytes (from %s)", len(payload), request.remote.hostinfo)
        return aiocoap.Message(
            payload=payload.encode("utf-8"),
            content_format=50,  # application/json
        )


# ---------------------------------------------------------------------------
# LwM2M resources
# ---------------------------------------------------------------------------


class LwM2MResource(resource.Resource):
    """Generic LwM2M resource -- returns a fixed value for GET."""

    def __init__(self, value: str, description: str = ""):
        super().__init__()
        self._value = value
        self._description = description

    async def render_get(self, request):
        logger.info(
            "GET %s -> %s (%s) (from %s)",
            request.opt.uri_path,
            self._value,
            self._description,
            request.remote.hostinfo,
        )
        return aiocoap.Message(
            payload=self._value.encode("utf-8"),
            content_format=0,
        )


class LwM2MTimestampResource(resource.Resource):
    """LwM2M current time resource -- returns Unix timestamp."""

    async def render_get(self, request):
        ts = str(int(time.time()))
        logger.info("GET /3/0/13 -> %s (from %s)", ts, request.remote.hostinfo)
        return aiocoap.Message(
            payload=ts.encode("utf-8"),
            content_format=0,
        )


# ---------------------------------------------------------------------------
# Server setup
# ---------------------------------------------------------------------------


def build_resource_tree() -> resource.Site:
    """Build the CoAP resource tree with all mock resources."""
    root = resource.Site()

    # Standard sensor resources (observable)
    root.add_resource(
        ["sensor", "temperature"],
        TemperatureResource(),
    )
    root.add_resource(
        ["sensor", "humidity"],
        HumidityResource(),
    )
    root.add_resource(
        ["sensor", "pressure"],
        PressureResource(),
    )
    root.add_resource(
        ["sensor", "large-data"],
        LargeDataResource(),
    )

    # Content format resources
    root.add_resource(
        ["sensor", "data.cbor"],
        CborSensorResource(),
    )
    root.add_resource(
        ["sensor", "measurements"],
        SenMLResource(),
    )

    # Actuator resources (writable without auth)
    root.add_resource(["actuator", "led"], LedResource())
    root.add_resource(["actuator", "relay"], RelayResource())
    root.add_resource(["actuator", "valve"], ValveResource())

    # Configuration
    root.add_resource(["config"], ConfigResource())

    # Read-only informational
    root.add_resource(["firmware", "version"], FirmwareVersionResource())
    root.add_resource(["time"], TimeResource())
    root.add_resource(["device"], DeviceResource())

    # LwM2M Device Object /3/0
    root.add_resource(
        ["3", "0", "0"],
        LwM2MResource("OIDA-Test", "Manufacturer"),
    )
    root.add_resource(
        ["3", "0", "1"],
        LwM2MResource("CoAP-Mock-v1", "Model"),
    )
    root.add_resource(
        ["3", "0", "2"],
        LwM2MResource("SN-2024-001337", "Serial Number"),
    )
    root.add_resource(
        ["3", "0", "3"],
        LwM2MResource("1.2.3-beta", "Firmware Version"),
    )
    root.add_resource(
        ["3", "0", "9"],
        LwM2MResource("87", "Battery Level"),
    )
    root.add_resource(
        ["3", "0", "13"],
        LwM2MTimestampResource(),
    )

    # LwM2M Security Object /0/0 -- NoSec mode (intentional security finding)
    root.add_resource(
        ["0", "0", "2"],
        LwM2MResource("3", "Security Mode (3=NoSec)"),
    )

    # LwM2M Server Object /1/0
    root.add_resource(
        ["1", "0", "1"],
        LwM2MResource("3600", "Lifetime"),
    )

    # LwM2M Firmware Update Object /5/0
    root.add_resource(
        ["5", "0", "3"],
        LwM2MResource("0", "Firmware Update State"),
    )

    # LwM2M JSON representation of /3/0 Device Object
    root.add_resource(
        ["3", "0.json"],
        LwM2MJsonResource(),
    )

    # Explicitly register /.well-known/core (aiocoap does NOT auto-generate it)
    root.add_resource(
        [".well-known", "core"],
        resource.WKCResource(root.get_resources_as_linkheader),
    )

    return root


async def main(port: int = 5683, verbose: bool = False):
    """Start the CoAP mock server."""
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    root = build_resource_tree()

    logger.info("=" * 60)
    logger.info("OIDA CoAP Mock Server")
    logger.info("=" * 60)
    logger.info("  Port: %d/udp", port)
    logger.info("  Resources:")
    logger.info("    /sensor/temperature   (observable, text/plain)")
    logger.info("    /sensor/humidity      (observable, text/plain)")
    logger.info("    /sensor/pressure      (observable, text/plain)")
    logger.info("    /sensor/large-data    (GET, >2KB JSON, block-wise)")
    logger.info("    /sensor/data.cbor     (GET, CBOR ct=60)")
    logger.info("    /sensor/measurements  (GET, SenML JSON ct=110)")
    logger.info("    /actuator/led         (GET/PUT, text/plain)")
    logger.info("    /actuator/relay       (GET/PUT, text/plain)")
    logger.info("    /actuator/valve       (GET/PUT, text/plain)")
    logger.info("    /config               (GET/PUT/FETCH/PATCH/iPATCH, JSON)")
    logger.info("    /firmware/version     (GET, text/plain)")
    logger.info("    /time                 (GET, text/plain)")
    logger.info("    /device               (GET, application/json)")
    logger.info("    /3/0.json             (GET, LwM2M JSON ct=11543)")
    logger.info("  LwM2M:")
    logger.info("    /3/0/0  = OIDA-Test        (manufacturer)")
    logger.info("    /3/0/1  = CoAP-Mock-v1     (model)")
    logger.info("    /3/0/2  = SN-2024-001337   (serial)")
    logger.info("    /3/0/3  = 1.2.3-beta       (firmware)")
    logger.info("    /3/0/9  = 87               (battery)")
    logger.info("    /3/0/13 = <unix timestamp> (time)")
    logger.info("    /0/0/2  = 3                (NoSec mode)")
    logger.info("    /1/0/1  = 3600             (lifetime)")
    logger.info("    /5/0/3  = 0                (fw update state)")
    logger.info("  Security findings:")
    logger.info("    - PUT to /actuator/* succeeds without authentication")
    logger.info("    - /0/0/2 = 3 (NoSec mode) -- no DTLS encryption")
    logger.info("=" * 60)

    bind = ("0.0.0.0", port)
    await aiocoap.Context.create_server_context(root, bind=bind)

    logger.info("CoAP server listening on port %d", port)

    # Run forever
    await asyncio.get_event_loop().create_future()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CoAP Mock Server for OIDA testing")
    parser.add_argument("--port", type=int, default=5683, help="UDP port (default: 5683)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    try:
        asyncio.run(main(port=args.port, verbose=args.verbose))
    except KeyboardInterrupt:
        logger.info("Shutting down CoAP mock server...")
