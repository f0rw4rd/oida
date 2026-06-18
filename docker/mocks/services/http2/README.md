# HTTP/2 Fuzzing Testbed

Two complementary HTTP/2 servers for protocol fuzzing with frame-level feedback.

## Services

| Service | Ports | Description |
|---------|-------|-------------|
| `http2-nghttp2` | 8443 (TLS), 8080 (h2c) | nghttp2 server with verbose frame logging |
| `http2-python` | 9443 (TLS), 9080 (h2c) | hyper-h2 server with validation callbacks |
| `http2-h2spec` | - | RFC conformance testing (on-demand) |

## Quick Start

```bash
# Build and start HTTP/2 services
cd docker/mocks
docker compose build http2-nghttp2 http2-python
docker compose up -d http2-nghttp2 http2-python

# Verify services are running
docker compose ps | grep http2

# Test with curl
curl --http2-prior-knowledge http://localhost:8080/
curl --http2-prior-knowledge http://localhost:9080/
```

## Diagnostic Endpoints (Python server only)

| Endpoint | Description |
|----------|-------------|
| `/.well-known/h2/state` | Server statistics and connection state |
| `/.well-known/h2/frames` | Recent frame event log (JSON) |
| `/.well-known/h2/errors` | Protocol errors detected |
| `/.well-known/h2/hpack` | HPACK dynamic table state |
| `/echo` | Echo request headers and body |
| `/status/{code}` | Return specific HTTP status code |
| `/delay/{seconds}` | Delayed response |

Example:
```bash
curl --http2-prior-knowledge http://localhost:9080/.well-known/h2/errors
```

## Using with OIDA Fuzzer

```python
import hpack
from oida.fuzz.monitors import HTTP2Monitor

# Encode headers using the hpack library (same as the fuzzer does)
encoder = hpack.Encoder()
encoder.header_table_size = 0
headers_block = encoder.encode([
    (b":method", b"GET"),
    (b":path", b"/test"),
    (b":scheme", b"http"),
    (b":authority", b"localhost:9080"),
])

# Create monitor for health checking
monitor = HTTP2Monitor(
    host="localhost",
    port=9080,
    use_tls=False,
    timeout=5.0
)

# Establish baseline
monitor.establish_baseline()

# Check for protocol errors during fuzzing
errors = monitor.get_error_summary()
frames = monitor.get_frame_log(limit=50)
```

## Frame-Level Logging

### nghttp2 (verbose mode)
The nghttp2 server outputs frame-level information:
```
[  0.001] recv SETTINGS frame <length=12, flags=0x00, stream_id=0>
[  0.002] send SETTINGS frame <length=0, flags=0x01, stream_id=0>
[  0.003] recv HEADERS frame <length=39, flags=0x05, stream_id=1>
```

Logs are written to `/var/log/http2/nghttpd_frames.jsonl` in the container.

### Python server (event callbacks)
The Python server logs structured events:
```json
{
  "timestamp": "2026-02-06T12:34:56.789Z",
  "event_type": "REQUEST_RECEIVED",
  "stream_id": 1,
  "frame_type": "HEADERS",
  "headers": [[":method", "GET"], [":path", "/"]]
}
```

## Protocol Error Detection

The Python server detects and reports:
- HPACK decoding errors
- Invalid pseudo-header order
- Connection-specific headers (forbidden in HTTP/2)
- Missing required pseudo-headers
- Uppercase header names
- Stream reset errors
- Flow control violations

## h2spec Conformance Testing

Run RFC conformance tests against the servers:
```bash
# Start h2spec container
docker compose --profile http2-test up -d http2-h2spec

# Run tests against Python server
docker exec http2-h2spec h2spec -h http2-python -p 9080

# Run tests against nghttp2
docker exec http2-h2spec h2spec -h http2-nghttp2 -p 8080
```

## Environment Variables

### Python Server
| Variable | Default | Description |
|----------|---------|-------------|
| `HTTP2_LOG_LEVEL` | INFO | Logging level |
| `HTTP2_VALIDATE_HEADERS` | true | Enable header validation |
| `HTTP2_LOG_HPACK` | true | Log HPACK operations |
| `HTTP2_LOG_FRAMES` | true | Log frame events |
| `HTTP2_ENABLE_TLS` | true | Enable TLS listener |
| `HTTP2_ENABLE_H2C` | true | Enable cleartext listener |

### nghttp2 Server
| Variable | Default | Description |
|----------|---------|-------------|
| `HTTP2_VERBOSE` | true | Enable verbose output |
| `HTTP2_HEXDUMP` | false | Enable frame hexdump |
| `HTTP2_LOG_FRAMES` | true | Parse frames to JSON |
