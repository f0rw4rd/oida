"""
Shared batched register reading utilities for Modbus.

Provides a single implementation of batched register reads used by
scanner.py, monitor.py, fuzz.py, and nxc_connection.py.
"""

from logging import Logger
from typing import Any, Dict, List, Optional, Tuple

# Canonical register type names used by pymodbus read methods.
_TYPE_ALIASES = {
    "holding": "holding_registers",
    "input": "input_registers",
    "coil": "coils",
    "discrete": "discrete_inputs",
    # Already canonical -- pass through.
    "holding_registers": "holding_registers",
    "input_registers": "input_registers",
    "coils": "coils",
    "discrete_inputs": "discrete_inputs",
}

# Map canonical type -> (read method name, response attribute).
_READ_INFO = {
    "holding_registers": ("read_holding_registers", "registers"),
    "input_registers": ("read_input_registers", "registers"),
    "coils": ("read_coils", "bits"),
    "discrete_inputs": ("read_discrete_inputs", "bits"),
}


def normalize_register_type(reg_type: str) -> str:
    """Map short names (``"holding"``) to canonical (``"holding_registers"``).

    Returns *reg_type* unchanged when it is already canonical or unknown.
    """
    return _TYPE_ALIASES.get(reg_type, reg_type)


def build_batches(addresses: List[int], max_batch: int) -> List[Tuple[int, int, List[int]]]:
    """Split *addresses* into contiguous runs capped at *max_batch*.

    Returns a list of ``(start_addr, count, addr_list)`` tuples.
    """
    if not addresses:
        return []

    batches: List[Tuple[int, int, List[int]]] = []
    run_start = addresses[0]
    run_addrs: List[int] = [run_start]

    for addr in addresses[1:]:
        if addr == run_addrs[-1] + 1 and len(run_addrs) < max_batch:
            run_addrs.append(addr)
        else:
            batches.append((run_start, len(run_addrs), list(run_addrs)))
            run_start = addr
            run_addrs = [addr]

    batches.append((run_start, len(run_addrs), list(run_addrs)))
    return batches


def read_registers_batched(
    client: Any,
    register_type: str,
    addresses: List[int],
    unit_id: int = 1,
    max_batch: Optional[int] = None,
    fallback_individual: bool = True,
    logger: Optional[Logger] = None,
) -> Dict[int, Any]:
    """Batch-read Modbus registers and return ``{addr: value}``.

    Parameters
    ----------
    client:
        A pymodbus synchronous client (or any object with the standard
        ``read_holding_registers`` / ``read_coils`` / etc. methods).
    register_type:
        Canonical (``"holding_registers"``) or short (``"holding"``) name.
    addresses:
        Sorted list of register addresses to read.
    unit_id:
        Modbus slave / device ID.
    max_batch:
        Maximum registers per request.  ``None`` picks the Modbus spec
        default (125 for holding/input, 2000 for coils/discrete).
    fallback_individual:
        When ``True``, failed batches are re-read one address at a time.
        When ``False``, failed addresses are silently skipped (useful for
        monitoring loops where speed matters more than completeness).
    logger:
        Optional logger for debug messages.
    """
    canonical = normalize_register_type(register_type)
    info = _READ_INFO.get(canonical)
    if info is None or not addresses:
        return {}

    read_method_name, attr_name = info

    # Default batch sizes per Modbus spec.
    if max_batch is None:
        max_batch = 2000 if canonical in ("coils", "discrete_inputs") else 125

    read_fn = getattr(client, read_method_name, None)
    if read_fn is None:
        return {}

    batches = build_batches(addresses, max_batch)
    values: Dict[int, Any] = {}

    for batch_start, batch_count, batch_addrs in batches:
        try:
            result = read_fn(batch_start, count=batch_count, device_id=unit_id)

            if result is not None and not result.isError():
                data = getattr(result, attr_name, None)
                if data is not None and len(data) >= batch_count:
                    for i, addr in enumerate(batch_addrs):
                        values[addr] = data[i]
                    continue
            # Batch failed or returned short response.
            if fallback_individual:
                _read_individual(read_fn, attr_name, batch_addrs, unit_id, values, logger)

        except Exception:
            if logger:
                logger.debug(
                    "Batch read failed for %s addresses %d-%d, falling back",
                    canonical,
                    batch_addrs[0],
                    batch_addrs[-1],
                )
            if fallback_individual:
                _read_individual(read_fn, attr_name, batch_addrs, unit_id, values, logger)

    return values


def _read_individual(
    read_fn: Any,
    attr_name: str,
    addrs: List[int],
    unit_id: int,
    out: Dict[int, Any],
    logger: Optional[Logger] = None,
) -> None:
    """Read addresses one at a time, storing successes in *out*."""
    for addr in addrs:
        try:
            result = read_fn(addr, count=1, device_id=unit_id)
            if result is not None and not result.isError():
                data = getattr(result, attr_name, None)
                if data:
                    out[addr] = data[0]
        except Exception as e:
            if logger:
                logger.debug("Individual read failed at %d: %s", addr, e)
