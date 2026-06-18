#!/usr/bin/env python3
"""Benchmark: parallel pyshark FileCapture vs sequential single-pass.

Each worker opens the *same* pcap file with its own display_filter, so
tshark reads all packets (full TCP reassembly) but only outputs matches.
OS page cache makes re-reading near-free after the first worker.

Supports three execution modes:
  - sequential:      single-pass with combined display filter
  - parallel-sync:   ProcessPoolExecutor with synchronous as_completed()
  - parallel-async:  asyncio event loop dispatching workers via run_in_executor()

Usage:
    python scripts/bench_parallel_pcap.py <pcap_file>
    python scripts/bench_parallel_pcap.py <pcap_file> --workers 4
    python scripts/bench_parallel_pcap.py <pcap_file> --protocols ics
    python scripts/bench_parallel_pcap.py <pcap_file> --mode parallel-async
"""

import argparse
import asyncio
import os
import sys
import time
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import cpu_count

# Ensure project root is importable when run as a script
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _project_root not in sys.path:
    sys.path.insert(0, os.path.join(_project_root, "src"))


# ---------------------------------------------------------------------------
# Worker function — must be module-level (picklable by multiprocessing)
# ---------------------------------------------------------------------------


def _worker(pcap_file, display_filter, listener_names, decode_as):
    """Process one filter group on the full pcap file.

    Returns a plain dict (picklable) with timing and result counts.
    """
    import pyshark
    from oida.protocols.pcap.listener_registry import create_listeners

    t0 = time.time()
    listeners = create_listeners(set(listener_names))

    cap_kwargs = {
        "keep_packets": False,
        "display_filter": display_filter,
    }
    if decode_as:
        cap_kwargs["decode_as"] = decode_as

    cap = pyshark.FileCapture(pcap_file, **cap_kwargs)

    # Build layer dispatch table (same approach as PcapScanner)
    layer_dispatch = defaultdict(list)
    always_listeners = []
    for listener in listeners.values():
        required = getattr(listener, "REQUIRED_LAYERS", ())
        if required:
            for layer_name in required:
                layer_dispatch[layer_name].append(listener)
        else:
            always_listeners.append(listener)

    pkt_count = 0
    for pkt in cap:
        pkt_count += 1
        matched_ids = set()
        for layer in pkt.layers:
            for listener in layer_dispatch.get(layer.layer_name.lower(), ()):
                lid = id(listener)
                if lid not in matched_ids:
                    matched_ids.add(lid)
                    try:
                        listener.feed_packet(pkt)
                    except Exception:
                        pass
        for listener in always_listeners:
            try:
                listener.feed_packet(pkt)
            except Exception:
                pass

    cap.close()
    elapsed = time.time() - t0

    results = {}
    for name, listener in listeners.items():
        results[name] = {
            "devices": len(listener.discovered_devices),
            "credentials": len(getattr(listener, "credentials", [])),
        }

    return {
        "filter": display_filter,
        "listener_names": listener_names,
        "packet_count": pkt_count,
        "elapsed": elapsed,
        "listeners": results,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Broad filters that would match almost everything — skip these for grouping
_BROAD_TOKENS = {"data", "tcp.payload", "udp.payload"}


def _is_broad_filter(display_filter):
    tokens = display_filter.replace("||", " ").replace("|", " ").split()
    return any(t in _BROAD_TOKENS for t in tokens)


def _collect_filter_groups(listener_names):
    """Group listener names by their DISPLAY_FILTER.

    Returns list of (display_filter, [listener_name, ...]) tuples.
    Listeners with broad/empty filters are collected into a None group.
    """
    from oida.protocols.pcap.listener_registry import LISTENER_REGISTRY, create_listeners

    # Instantiate to read class-level DISPLAY_FILTER
    listeners = create_listeners(listener_names)

    groups = defaultdict(list)
    skipped = []
    for name, listener in listeners.items():
        df = getattr(listener, "DISPLAY_FILTER", "")
        if not df or _is_broad_filter(df):
            skipped.append(name)
            continue
        groups[df].append(name)

    result = [(df, names) for df, names in sorted(groups.items())]
    if skipped:
        result.append((None, skipped))
    return result


def _build_combined_filter(filter_groups):
    """Build a single OR'd display filter from all groups (for sequential baseline)."""
    parts = []
    for df, _ in filter_groups:
        if df is None:
            continue
        parts.append(f"({df})" if " " in df else df)
    if parts:
        return " or ".join(sorted(set(parts)))
    return None


def _print_listener_summary(listeners):
    """Print non-empty listener results."""
    for name, data in sorted(listeners.items()):
        if data["devices"] or data["credentials"]:
            print(f"    {name}: {data['devices']} devices, {data['credentials']} creds")


def _merge_worker_listeners(worker_results):
    """Merge listener dicts from multiple worker results."""
    merged = {}
    for res in worker_results:
        merged.update(res["listeners"])
    return merged


# ---------------------------------------------------------------------------
# Sequential baseline
# ---------------------------------------------------------------------------


def run_sequential(pcap_file, filter_groups, decode_as):
    """Single-pass FileCapture with combined display filter."""
    all_names = []
    for _, names in filter_groups:
        all_names.extend(names)

    combined = _build_combined_filter(filter_groups)
    print(f"\n--- Sequential baseline ({len(all_names)} listeners) ---")
    if combined:
        print(f"  display_filter: {combined[:100]}{'...' if len(combined or '') > 100 else ''}")

    result = _worker(pcap_file, combined, all_names, decode_as)

    print(f"  packets:  {result['packet_count']}")
    print(f"  time:     {result['elapsed']:.1f}s")
    print(
        f"  pkt/s:    {result['packet_count'] / result['elapsed']:.0f}"
        if result["elapsed"] > 0
        else ""
    )

    _print_listener_summary(result["listeners"])
    return result


# ---------------------------------------------------------------------------
# Parallel run (synchronous dispatch)
# ---------------------------------------------------------------------------


def run_parallel(pcap_file, filter_groups, decode_as, max_workers):
    """One worker per filter group, ProcessPoolExecutor with sync as_completed()."""
    # Only submit groups that have a real display filter
    tasks = [(df, names) for df, names in filter_groups if df is not None]

    print(f"\n--- Parallel-sync ({len(tasks)} workers, max_workers={max_workers}) ---")

    worker_results = []
    t0 = time.time()

    with ProcessPoolExecutor(max_workers=max_workers) as pool:
        futures = {}
        for df, names in tasks:
            fut = pool.submit(_worker, pcap_file, df, names, decode_as)
            futures[fut] = (df, names)

        for fut in as_completed(futures):
            df, names = futures[fut]
            try:
                res = fut.result()
                worker_results.append(res)
                print(
                    f"  [{res['elapsed']:5.1f}s] filter={df[:40]:<40s}  "
                    f"pkts={res['packet_count']:<6d}  listeners={','.join(names)}"
                )
            except Exception as e:
                print(f"  [ERROR] filter={df}: {e}")

    total_elapsed = time.time() - t0
    total_pkts = sum(r["packet_count"] for r in worker_results)

    print(f"  wall-clock: {total_elapsed:.1f}s  (total pkts across workers: {total_pkts})")

    merged = _merge_worker_listeners(worker_results)
    _print_listener_summary(merged)

    return {
        "elapsed": total_elapsed,
        "total_packets": total_pkts,
        "listeners": merged,
        "worker_results": worker_results,
    }


# ---------------------------------------------------------------------------
# Parallel run (async dispatch)
# ---------------------------------------------------------------------------


async def _progress_monitor(queue, total_workers):
    """Print live progress as workers complete."""
    completed = 0
    while completed < total_workers:
        res = await queue.get()
        completed += 1
        if isinstance(res, Exception):
            print(f"  [{completed}/{total_workers}] ERROR: {res}")
        else:
            df = res["filter"] or "(no filter)"
            names = res["listener_names"]
            print(
                f"  [{completed}/{total_workers}] [{res['elapsed']:5.1f}s] "
                f"filter={df[:40]:<40s}  "
                f"pkts={res['packet_count']:<6d}  listeners={','.join(names)}"
            )


async def run_parallel_async(pcap_file, filter_groups, decode_as, max_workers):
    """One worker per filter group, asyncio event loop with run_in_executor()."""
    tasks = [(df, names) for df, names in filter_groups if df is not None]

    print(f"\n--- Parallel-async ({len(tasks)} workers, max_workers={max_workers}) ---")

    loop = asyncio.get_event_loop()
    pool = ProcessPoolExecutor(max_workers=max_workers)
    progress_queue = asyncio.Queue()

    async def _run_and_report(df, names):
        try:
            res = await loop.run_in_executor(pool, _worker, pcap_file, df, names, decode_as)
            await progress_queue.put(res)
            return res
        except Exception as e:
            await progress_queue.put(e)
            raise

    t0 = time.time()

    # Launch progress monitor and all workers concurrently
    monitor = asyncio.ensure_future(_progress_monitor(progress_queue, len(tasks)))
    coros = [_run_and_report(df, names) for df, names in tasks]
    results = await asyncio.gather(*coros, return_exceptions=True)
    await monitor

    pool.shutdown(wait=False)
    total_elapsed = time.time() - t0

    # Separate successes from errors
    worker_results = []
    for r in results:
        if isinstance(r, Exception):
            print(f"  [ERROR] {r}")
        else:
            worker_results.append(r)

    total_pkts = sum(r["packet_count"] for r in worker_results)
    print(f"  wall-clock: {total_elapsed:.1f}s  (total pkts across workers: {total_pkts})")

    merged = _merge_worker_listeners(worker_results)
    _print_listener_summary(merged)

    return {
        "elapsed": total_elapsed,
        "total_packets": total_pkts,
        "listeners": merged,
        "worker_results": worker_results,
    }


async def run_sequential_async(pcap_file, filter_groups, decode_as):
    """Sequential baseline using run_in_executor (for consistent async interface)."""
    all_names = []
    for _, names in filter_groups:
        all_names.extend(names)

    combined = _build_combined_filter(filter_groups)
    print(f"\n--- Sequential baseline ({len(all_names)} listeners) ---")
    if combined:
        print(f"  display_filter: {combined[:100]}{'...' if len(combined or '') > 100 else ''}")

    loop = asyncio.get_event_loop()
    pool = ProcessPoolExecutor(max_workers=1)
    result = await loop.run_in_executor(pool, _worker, pcap_file, combined, all_names, decode_as)
    pool.shutdown(wait=False)

    print(f"  packets:  {result['packet_count']}")
    print(f"  time:     {result['elapsed']:.1f}s")
    print(
        f"  pkt/s:    {result['packet_count'] / result['elapsed']:.0f}"
        if result["elapsed"] > 0
        else ""
    )

    _print_listener_summary(result["listeners"])
    return result


# ---------------------------------------------------------------------------
# Correctness check
# ---------------------------------------------------------------------------


def check_correctness(label_a, result_a, label_b, result_b):
    """Compare device and credential counts between two runs."""
    print(f"\n--- Correctness: {label_a} vs {label_b} ---")
    listeners_a = result_a["listeners"]
    listeners_b = result_b["listeners"]

    all_names = sorted(set(listeners_a.keys()) | set(listeners_b.keys()))
    ok = True
    for name in all_names:
        a = listeners_a.get(name, {"devices": 0, "credentials": 0})
        b = listeners_b.get(name, {"devices": 0, "credentials": 0})
        match = a == b
        mark = "OK" if match else "MISMATCH"
        if not match:
            ok = False
        if a["devices"] or a["credentials"] or b["devices"] or b["credentials"]:
            print(
                f"  {mark:8s} {name:<16s}  "
                f"{label_a}=({a['devices']}d,{a['credentials']}c)  "
                f"{label_b}=({b['devices']}d,{b['credentials']}c)"
            )

    if ok:
        print("  All counts match.")
    else:
        print("  WARNING: Mismatches detected (may be due to skipped broad-filter listeners).")
    return ok


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

MODES = ("all", "sequential", "parallel-sync", "parallel-async")


async def async_main(args):
    """Async orchestration of benchmark modes."""
    from oida.protocols.pcap.listener_registry import resolve_listener_names
    from oida.protocols.pcap.scanner import DEFAULT_DECODE_AS_HINTS

    file_size = os.path.getsize(args.pcap_file)
    print(f"PCAP: {args.pcap_file} ({file_size / 1024 / 1024:.1f} MB)")

    # Resolve listener names
    protocols = [p.strip() for p in args.protocols.split(",")] if args.protocols else None
    listener_names = resolve_listener_names(protocols=protocols, quick=args.quick)
    print(f"Listeners: {len(listener_names)} ({', '.join(sorted(listener_names))})")

    decode_as = dict(DEFAULT_DECODE_AS_HINTS)

    # Group by display filter
    filter_groups = _collect_filter_groups(listener_names)
    print(f"\nFilter groups ({len(filter_groups)}):")
    for df, names in filter_groups:
        label = df if df else "(broad/no filter — skipped in parallel)"
        print(f"  {label[:60]:<60s}  -> {', '.join(names)}")

    mode = args.mode
    results = {}

    # --- Sequential ---
    # Always use async variant: _worker() calls PyShark which uses asyncio
    # internally, so it cannot run directly inside an already-running event loop.
    # run_in_executor() puts it in a subprocess, avoiding the conflict.
    if mode in ("all", "sequential"):
        results["seq"] = await run_sequential_async(args.pcap_file, filter_groups, decode_as)

    # --- Parallel-sync ---
    # run_parallel() uses synchronous as_completed() which blocks the loop,
    # but all workers run in subprocesses so no event loop conflict.
    # Wrap in run_in_executor to avoid blocking the async loop.
    if mode in ("all", "parallel-sync"):
        loop = asyncio.get_event_loop()
        results["par_sync"] = await loop.run_in_executor(
            None, run_parallel, args.pcap_file, filter_groups, decode_as, args.workers
        )

    # --- Parallel-async ---
    if mode in ("all", "parallel-async"):
        results["par_async"] = await run_parallel_async(
            args.pcap_file, filter_groups, decode_as, args.workers
        )

    # --- Summary ---
    print("\n" + "=" * 70)
    if "seq" in results:
        seq = results["seq"]
        pkt_count = seq.get("packet_count", seq.get("total_packets", 0))
        print(f"{'Sequential:':<18s} {seq['elapsed']:6.1f}s  ({pkt_count} packets)")
    if "par_sync" in results:
        ps = results["par_sync"]
        print(
            f"{'Parallel-sync:':<18s} {ps['elapsed']:6.1f}s  "
            f"({ps['total_packets']} packets across {len(ps['worker_results'])} workers)"
        )
    if "par_async" in results:
        pa = results["par_async"]
        print(
            f"{'Parallel-async:':<18s} {pa['elapsed']:6.1f}s  "
            f"({pa['total_packets']} packets across {len(pa['worker_results'])} workers)"
        )

    # Speedup calculations
    if "seq" in results:
        seq_time = results["seq"]["elapsed"]
        if seq_time > 0:
            if "par_sync" in results:
                print(f"{'Speedup (sync):':<18s} {seq_time / results['par_sync']['elapsed']:.2f}x")
            if "par_async" in results:
                print(
                    f"{'Speedup (async):':<18s} {seq_time / results['par_async']['elapsed']:.2f}x"
                )
    if "par_sync" in results and "par_async" in results:
        ps_time = results["par_sync"]["elapsed"]
        pa_time = results["par_async"]["elapsed"]
        if ps_time > 0:
            diff_pct = ((pa_time - ps_time) / ps_time) * 100
            print(f"{'Async vs sync:':<18s} {diff_pct:+.1f}%")
    print("=" * 70)

    # Correctness checks
    if "seq" in results and "par_sync" in results:
        check_correctness("seq", results["seq"], "par-sync", results["par_sync"])
    if "seq" in results and "par_async" in results:
        check_correctness("seq", results["seq"], "par-async", results["par_async"])
    if "par_sync" in results and "par_async" in results and "seq" not in results:
        check_correctness("par-sync", results["par_sync"], "par-async", results["par_async"])


def main():
    parser = argparse.ArgumentParser(description="Benchmark parallel pyshark FileCapture")
    parser.add_argument("pcap_file", help="Path to pcap/pcapng file")
    parser.add_argument(
        "--workers",
        type=int,
        default=min(cpu_count(), 8),
        help="Max parallel workers (default: min(cpu_count, 8))",
    )
    parser.add_argument(
        "--protocols", help="Comma-separated protocol/tag filter (e.g. ics,credential)"
    )
    parser.add_argument("--quick", action="store_true", help="Use quick-scan listener preset")
    parser.add_argument(
        "--mode",
        choices=MODES,
        default="all",
        help="Benchmark mode: all (default), sequential, parallel-sync, parallel-async",
    )
    args = parser.parse_args()

    if not os.path.isfile(args.pcap_file):
        print(f"Error: file not found: {args.pcap_file}", file=sys.stderr)
        sys.exit(1)

    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()
