# OIDA Python Style Guide

This document establishes coding standards for the OIDA framework.

## Table of Contents
1. [Formatting Rules](#formatting-rules)
2. [Dependency Handling](#dependency-handling)
3. [Class Definitions](#class-definitions)
4. [Error Handling](#error-handling)
5. [Constants and Magic Numbers](#constants-and-magic-numbers)
6. [Type Hints](#type-hints)
7. [Docstrings](#docstrings)
8. [Naming Conventions](#naming-conventions)
9. [File Organization](#file-organization)

---

## Formatting Rules

- **Line length**: 100 characters.
- **Indentation**: 4 spaces (no tabs).
- **String quotes**: Double quotes preferred (ruff default).
- **Formatter & linter**: `ruff format src/oida/ tests/` and `ruff check src/oida/ tests/`.
- **Type checking**: `mypy src/oida/` (informational, not a CI gate yet).
- **Dead-code detection**: `vulture src/oida/ .vulture_whitelist.py --min-confidence 80`.
- **Security lint**: `bandit -r src/oida/ -c pyproject.toml`.

### Import Order (isort)

```python
# 1. Standard library
import socket
from typing import Dict, Any, Optional, TYPE_CHECKING
from datetime import datetime

# 2. Third-party (with lazy import for optional deps)
from ..utils.lazy_import import lazy_import

# 3. Local imports
from ..utils import module, NetworkScanner
from ..utils.exceptions import DependencyError
```

---

## Dependency Handling

### Lazy Import Pattern (Required for Protocol Dependencies)

Protocol modules MUST use lazy imports to prevent hard failures when optional
dependencies are not installed. This allows the CLI to show help and list
available protocols even when some dependencies are missing.

```python
from typing import TYPE_CHECKING
from ..utils.lazy_import import lazy_import
from ..utils.exceptions import DependencyError

# Type hints only - no runtime import cost
if TYPE_CHECKING:
    import pyads as pyads_type

# Lazy import - only loads when actually used
_pyads = lazy_import("pyads", "ADS", "pip install pyads")


def _get_pyads():
    """Get pyads module, raising DependencyError if not available."""
    return _pyads()


class ADSScanner(NetworkScanner):
    def check_dependencies(self) -> bool:
        """Check if pyads is available."""
        return _pyads.is_available

    def connect(self) -> Any:
        """Establish ADS connection."""
        pyads = _get_pyads()  # Lazy load here
        pyads.open_port()
        # ... rest of connection logic
```

### Lazy Proxy Pattern (For Complex Modules)

When a module has many submodule imports (like `asyncua.ua`), use a lazy proxy:

```python
class _LazyUaModule:
    """Lazy proxy for asyncua.ua module."""

    def __getattr__(self, name):
        ua_module = _get_ua_module()
        return getattr(ua_module, name)

# Can be used like normal: ua.AttributeIds, ua.NodeClass
ua = _LazyUaModule()
```

### create_protocol_module Pattern

```python
# The lambda returns True when deps are MISSING (inverted check)
metadata, run = create_protocol_module(
    ADSScanner,
    dependencies_check_func=lambda: not _pyads.is_available
)
```

---

## Class Definitions

### Protocol Scanner Class

```python
@register_protocol(
    name="Beckhoff ADS Scanner",
    description="ADS protocol scanner for TwinCAT PLC systems.",
    default_port=48898,
    authors=["f0rw4rd"],
    references=[
        {"type": "url", "ref": "https://www.beckhoff.com"},
    ],
    protocol_options=protocol_options,
)
class ADSScanner(NetworkScanner):
    """
    Beckhoff ADS protocol scanner.

    Supports symbol discovery, memory access, and state control
    for TwinCAT PLC systems.

    Attributes:
        ams_netid: Target AMS Net ID
        max_symbols: Maximum symbols to process
    """

    # Class constants
    DEFAULT_PORT = 48898
    DEFAULT_TIMEOUT = 5
    MAX_SYMBOLS_DEFAULT = 1000

    def __init__(self, args: Dict[str, Any]) -> None:
        super().__init__(args)
        self.ams_netid = args.get("ams-netid", "")
```

### NXC-Style Callable Class

```python
class ads(NetworkConnection):
    """NXC-style ADS scanner (callable on instantiation)."""

    def __init__(self, args, db, host):
        self.protocol_name = "ADS"
        self.default_port = 48898
        super().__init__(args, db, host)

    def proto_flow(self):
        """Main protocol workflow.

        ``proto_logger()`` is called automatically by ``NetworkConnection.__init__``
        before this method runs — do not call it here.
        """
        self.create_conn_obj()
        self.enum_host_info()
        self.print_host_info()
        # ... protocol-specific operations

    @staticmethod
    def check_dependencies() -> bool:
        return _pyads.is_available
```

---

## Error Handling

### Exception Classes

Use ICS-prefixed exceptions to avoid shadowing Python builtins:

```python
from ..utils.exceptions import (
    ICSConnectionError,    # Not ConnectionError
    ICSTimeoutError,       # Not TimeoutError
    DependencyError,
    ProtocolError,
)
```

### Exception Handling Pattern

```python
# GOOD - Specific exceptions with context and chaining
try:
    connection = self._connect()
except socket.timeout as e:
    raise ICSTimeoutError(
        f"Connection timed out after {self.timeout}s",
        protocol="ADS"
    ) from e
except socket.error as e:
    raise ICSConnectionError(
        f"Network error: {e}",
        protocol="ADS"
    ) from e

# BAD - Catching all exceptions
try:
    result = do_something()
except Exception as e:
    return {"error": str(e)}  # Don't return error dicts
```

### DependencyError Handling

```python
# In protocol methods that need the dependency
def create_conn_obj(self):
    if not _pyads.is_available:
        raise DependencyError(
            "pyads library required for ADS protocol.\n"
            "Install with: pip install pyads",
            protocol="ADS"
        )
    # ... connection logic
```

---

## Constants and Magic Numbers

### Module-Level Constants

```python
# Protocol constants
DEFAULT_PORT = 48898
DEFAULT_TIMEOUT_SECONDS = 5
MAX_RETRY_ATTEMPTS = 3
MEMORY_READ_CHUNK_SIZE = 4096

# State mappings
ADS_STATE_MAP = {
    0: "INVALID",
    1: "IDLE",
    5: "RUN",
    6: "STOP",
}

# Port mappings
ADS_PORT_MAP = {
    "TC3PLC1": 851,
    "TC3PLC2": 852,
    "NC": 500,
}
```

### Protocol Options Dict

```python
protocol_options = {
    "ams-netid": {
        "type": "string",
        "description": "Target AMS Net ID",
        "required": False,
        "default": "",
    },
    "max-symbols": {
        "type": "int",
        "description": "Maximum symbols to process",
        "required": False,
        "default": 1000,
    },
}
```

---

## Type Hints

### Public API Type Hints

```python
def scan_registers(
    self,
    start: int,
    count: int,
    unit_id: int = 1,
    timeout: Optional[float] = None,
) -> Dict[int, Any]:
    """Scan protocol registers."""
    ...
```

### TypedDict for Complex Returns

```python
from typing import TypedDict, List

class ScanResult(TypedDict):
    success: bool
    host: str
    port: int
    data: Dict[str, Any]
    errors: List[str]

class DeviceInfo(TypedDict):
    name: str
    version: str
    vendor: Optional[str]
```

### TYPE_CHECKING for Import-Only Types

```python
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pyads  # Only for type hints, no runtime import

def connect(self) -> "pyads.Connection":
    ...
```

---

## Docstrings

### Function/Method Docstrings

```python
def connect(self, timeout: Optional[float] = None) -> Any:
    """
    Establish protocol connection to target.

    Args:
        timeout: Connection timeout in seconds. Uses default if None.

    Returns:
        Connection object (type varies by protocol).

    Raises:
        ICSConnectionError: If connection fails.
        ICSTimeoutError: If connection times out.
        DependencyError: If required library not installed.
    """
```

### Class Docstrings

```python
class ADSScanner(NetworkScanner):
    """
    Beckhoff ADS protocol scanner.

    Supports symbol discovery, memory access, and state control
    for TwinCAT PLC systems.

    Attributes:
        ams_netid: Target AMS Net ID
        max_symbols: Maximum symbols to process

    Example:
        scanner = ADSScanner({"rhost": "192.168.1.100"})
        results = scanner.run_scan()
    """
```

---

## Naming Conventions

| Type | Convention | Example |
|------|------------|---------|
| Classes | PascalCase | `ADSScanner`, `ModbusDecoder` |
| NXC callables | lowercase | `ads`, `modbus`, `opcua` |
| Functions | snake_case | `scan_registers`, `get_device_info` |
| Constants | UPPER_SNAKE | `DEFAULT_PORT`, `MAX_SYMBOLS` |
| Private | _prefix | `_connect`, `_parse_response` |
| Module-private | __ | `__all__` |
| Lazy imports | _name | `_pyads`, `_asyncua` |
| Lazy getters | _get_name | `_get_pyads()`, `_get_c104()` |

---

## File Organization

### Protocol Package Structure

```
protocols/
  modbus/
    __init__.py      # Public exports, NXC class
    scanner.py       # ModbusScanner class
    decoder.py       # Data decoding utilities
    proto_args.py    # CLI argument definitions
```

### Single-File Protocol Structure

```python
# protocols/ads.py

# 1. Module docstring
"""Protocol description..."""

# 2. Imports (stdlib, third-party lazy, local)

# 3. Lazy import setup

# 4. Constants and mappings

# 5. Protocol options dict

# 6. Scanner class with @register_protocol

# 7. create_protocol_module call

# 8. if __name__ == "__main__" block

# 9. NXC-style callable class
```

### __init__.py Exports

```python
__all__ = [
    # Scanner class
    "ModbusScanner",
    # NXC callable
    "modbus",
    # Metadata
    "metadata",
    "run",
    # Constants
    "FUNCTION_CODES",
    "EXCEPTION_CODES",
]
```

---

## Protocol Implementation Checklist

When implementing a new protocol or updating an existing one:

- [ ] Uses lazy import for protocol-specific dependencies
- [ ] `check_dependencies()` returns `_dep.is_available`
- [ ] `create_protocol_module` uses `lambda: not _dep.is_available`
- [ ] Exception handling uses ICS-prefixed exceptions
- [ ] DependencyError includes install instructions
- [ ] Type hints on all public methods
- [ ] Docstrings on all public methods and classes
- [ ] Constants defined at module level (no magic numbers)
- [ ] NXC-style class defined with `check_dependencies()`
