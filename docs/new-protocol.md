# Adding a New Protocol to OIDA

Use `src/oida/protocols/ads/` as the primary reference -- clean two-layer separation without the complexity of modbus's many mixins.

## Architecture

OIDA uses a **two-layer design**:

| Layer | Base Class | Trigger | Used By |
|-------|-----------|---------|---------|
| **1 -- Scanner** | `NetworkScanner` / `SerialScanner` | Explicit `run_scan()` | Library consumers |
| **2 -- NXC Connection** | `NetworkConnection` / `SerialConnection` | Auto via `proto_flow()` on init | CLI (`oida <proto> <target>`) |

Both layers are required. Layer 2 typically wraps Layer 1 internally.

## Directory Structure

```
src/oida/protocols/<name>/
    __init__.py          # Re-exports NXC class, scanner, metadata
    scanner.py           # Layer 1: @register_protocol scanner class
    nxc_connection.py    # Layer 2: NXC callable class
    proto_args.py        # CLI argument definitions
    constants.py         # Protocol constants, enums, magic numbers
    helpers.py           # Shared functions for both layers (optional)
    mixins/              # Feature-specific mixins (optional)

tests/unit/<name>/
    __init__.py
    test_scanner.py
    test_nxc_connection.py
```

## Step-by-Step

### 1. Lazy-Import the Dependency

Always use `lazy_import()` -- never `try/except ImportError`. This lets the CLI show help for all protocols even when deps are missing.

```python
from ...utils.lazy_import import lazy_import
_mypkg = lazy_import("mypkg", "MyProto")
# Later: mypkg = _mypkg()  -- raises DependencyError if not installed
```

### 2. Create the Scanner (`scanner.py`)

Inherit from `NetworkScanner`, decorate with `@register_protocol`, call `create_protocol_module()` at module bottom.

```python
from typing import Dict, Any
from ...utils import register_protocol, create_protocol_module, NetworkScanner
from ...utils.lazy_import import lazy_import

_mypkg = lazy_import("mypkg", "MyProto")

protocol_options = {
    "custom-opt": {"type": "int", "description": "Protocol-specific option", "default": 1},
}

@register_protocol(
    name="MyProto Scanner",
    description="Scans MyProto devices",
    default_port=1234,
    authors=["yourname"],
    references=[{"type": "url", "ref": "https://example.com/spec"}],
    protocol_options=protocol_options,
)
class MyProtoScanner(NetworkScanner):
    def get_protocol_name(self) -> str:
        return "MyProto"

    def get_default_port(self) -> int:
        return 1234

    def check_dependencies(self) -> bool:
        return _mypkg.is_available

    def connect(self) -> Any:
        host, port = self.get_target_info()
        client = _mypkg().Client(host, port, timeout=self.timeout)
        client.connect()
        return client

    def disconnect(self, connection) -> None:
        if connection:
            connection.close()

    def discover(self, connection) -> Dict[str, Any]:
        info = connection.get_device_info()
        self.logger.success(f"Device: {info.get('name', 'unknown')}")
        return {"device_info": info}

# Required: module-level exports
metadata, run = create_protocol_module(
    MyProtoScanner, dependencies_check_func=lambda: not _mypkg.is_available
)
```

**Required methods:** `get_protocol_name()`, `get_default_port()`, `check_dependencies()`, `connect()`, `disconnect()`, `discover()`.

### 3. Create the NXC Connection (`nxc_connection.py`)

Set `protocol_name` and `default_port` **before** calling `super().__init__()`.

```python
from ...connection import NetworkConnection
from ...utils.lazy_import import lazy_import

_mypkg = lazy_import("mypkg", "MyProto")

class myproto(NetworkConnection):
    """NXC-style MyProto scanner"""

    def __init__(self, args, db, host):
        self.protocol_name = "MyProto"
        self.default_port = 1234
        super().__init__(args, db, host)  # triggers proto_flow()

    def proto_flow(self):
        self.proto_logger()  # must be first
        self.create_conn_obj()
        if not self.conn:
            self.results["success"] = False
            return
        try:
            self.enum_host_info()
            self.print_host_info()
            if getattr(self.args, "some_flag", False):
                self._do_something()
        finally:
            self.cleanup()

    def create_conn_obj(self):
        try:
            self.conn = _mypkg().Client(self.ip, self.args.port,
                                        timeout=getattr(self.args, "timeout", 2))
            self.conn.connect()
            self.logger.success(f"Connected to {self.ip}:{self.args.port}")
        except Exception as e:
            self.logger.fail(f"Connection failed: {e}")
            self.conn = None

    def enum_host_info(self):
        self.results["data"]["device_info"] = self.conn.get_device_info()

    def print_host_info(self):
        info = self.results["data"].get("device_info", {})
        self.logger.display(f"Device: {info.get('name', 'N/A')}")
```

**Key rules:**
- Class name is **lowercase**, matching the directory name -- the CLI loader uses it for lookup.
- `proto_flow()` must call `self.proto_logger()` first.
- Logging: `self.logger.display/success/fail/warning/debug()` -- never `print()`.
- Wrap work in `try/finally` with `self.cleanup()`.

### 4. Wire Up the Package (`__init__.py`)

```python
"""MyProto Protocol Scanner"""
from .nxc_connection import myproto
from .scanner import MyProtoScanner, metadata, run, protocol_options

__all__ = ["myproto", "MyProtoScanner", "metadata", "run", "protocol_options"]
```

### 5. Define CLI Arguments (`proto_args.py`)

Use factory functions from `oida.utils.proto_args_factory` for standard groups.

```python
from ...utils.proto_args_factory import (
    create_protocol_parser, add_network_options,
    add_output_options, add_dangerous_options,
)

def proto_args(parser, parents):
    p = create_protocol_parser(parser, name="myproto",
        help_text="MyProto scanner", description="Scan MyProto devices",
        parents=parents)

    p.add_argument("target", help="Target IP, CIDR range, or file")
    add_network_options(p, default_port=1234)
    add_output_options(p)
    add_dangerous_options(p)

    grp = p.add_argument_group("MyProto Options")
    grp.add_argument("--device-info", "-i", action="store_true",
                     help="Read device identification")
    return p
```

**Available factory functions** (in `src/oida/utils/proto_args_factory.py`):

| Function | Adds |
|----------|------|
| `create_protocol_parser()` | Subparser with standard setup |
| `add_target_argument()` | Positional target argument |
| `add_network_options()` | `--port`, `--timeout` |
| `add_auth_options()` | `--username`, `--password`, `--credentials` |
| `add_output_options()` | `-o`, `-f`, `-v`, `-d`, `--json-log` |
| `add_dangerous_options()` | `--confirm`, `--fuzz`, `--fuzz-iterations` |
| `add_scan_options()` | `--threads`, `--delay`, `--retries` |
| `add_discovery_options()` | `--discover`, `--quick`, `--full` |
| `add_monitor_options()` | `--monitor`, `--interval`, `--duration` |
| `add_serial_options()` | `--serial-port`, `--baudrate`, `--parity` |
| `add_tls_options()` | `--tls`, `--tls-cert`, `--tls-key`, `--tls-ca` |
| `add_listen_options()` | `--listen`, `--listen-time`, `--listen-filter` |
| `add_brute_options()` | `--brute`, `--wordlist`, `--default-creds` |
| `add_control_options()` | `--cpu-start`, `--cpu-stop`, `--restart` |

### 6. Register in `pyproject.toml`

The extra name **must match** the protocol directory name.

```toml
[project.optional-dependencies]
myproto = ["mypkg>=1.0.0"]  # or [] for pure-socket protocols
```

Add to the `all` extra: `"oida[myproto]"`.

### 7. Write Tests

Minimum: test scanner construction and protocol name. Mock the external dependency.

```python
# tests/unit/myproto/test_scanner.py
from unittest.mock import patch

class TestMyProtoScanner:
    @patch("oida.protocols.myproto.scanner._mypkg")
    def test_connect(self, mock_pkg):
        from oida.protocols.myproto.scanner import MyProtoScanner
        scanner = MyProtoScanner({"rhost": "127.0.0.1", "rport": 1234})
        conn = scanner.connect()
        assert conn is not None

    def test_protocol_name(self):
        from oida.protocols.myproto.scanner import MyProtoScanner
        scanner = MyProtoScanner.__new__(MyProtoScanner)
        assert scanner.get_protocol_name() == "MyProto"
```

### 8. Verify

```bash
ruff check --fix src/oida/protocols/myproto/ tests/unit/myproto/
ruff format src/oida/protocols/myproto/ tests/unit/myproto/
python -m pytest tests/unit/myproto/ -x -q
oida --help  # should list "myproto"
```

## Conventions Checklist

- [ ] Directory name is lowercase, matches pyproject.toml extra name
- [ ] NXC class name is lowercase, matches directory name
- [ ] Scanner class is PascalCase with `Scanner` suffix
- [ ] Dependencies use `lazy_import()`, never `try/except ImportError`
- [ ] Logging via `self.logger`, never `print()`
- [ ] `proto_flow()` calls `self.proto_logger()` first
- [ ] `@register_protocol` on scanner class; `create_protocol_module()` at bottom
- [ ] `proto_args()` signature: `def proto_args(parser, parents)`
- [ ] Operations default to read-only; dangerous ops require `--confirm`
- [ ] All socket operations have timeouts
- [ ] `OSError` not `socket.error`; `TimeoutError` not `socket.timeout`
- [ ] Type hints on public methods
- [ ] Tests in `tests/unit/<name>/`

## Reference Implementations

| Protocol | Complexity | Why |
|----------|-----------|-----|
| **ads** | Medium | Clean two-layer separation, best starting template |
| **snap7** | Medium | Scanner mixins, device lookup tables |
| **modbus** | High | Many mixins, multiple transports, most feature-complete |
