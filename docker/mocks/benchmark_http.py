#!/usr/bin/env python3
"""
Simple HTTP server for benchmarking fuzzer speed.

Tracks:
  - Requests per second (RPS)
  - Interval between requests
  - Valid vs Invalid (malformed) request ratio
  - Error type breakdown

Usage:
    python benchmark_http.py [port]

Example:
    python benchmark_http.py 8080
    # Then in another terminal:
    oida fuzz http 127.0.0.1 -p 8080 -v
"""

import sys
import time
import socket
import threading
from datetime import datetime

# Stats
stats = {
    "total": 0,
    "valid": 0,
    "invalid": 0,
    "start_time": None,
    "last_time": None,
    "intervals": [],
    "errors": {},  # error type -> count
}
stats_lock = threading.Lock()


def print_stats(final=False):
    """Print current statistics"""
    with stats_lock:
        now = time.time()
        elapsed = now - stats["start_time"] if stats["start_time"] else 0
        rps = stats["total"] / elapsed if elapsed > 0 else 0

        intervals = stats["intervals"]
        avg_interval = sum(intervals) / len(intervals) if intervals else 0
        min_interval = min(intervals) if intervals else 0
        max_interval = max(intervals) if intervals else 0

        valid_pct = (stats["valid"] / stats["total"] * 100) if stats["total"] > 0 else 0
        invalid_pct = (stats["invalid"] / stats["total"] * 100) if stats["total"] > 0 else 0

        if final:
            print("\n" + "=" * 70)
            print("FINAL STATS")
            print("=" * 70)
            print(f"Total requests:    {stats['total']:,}")
            print(f"  Valid:           {stats['valid']:,} ({valid_pct:.1f}%)")
            print(f"  Invalid:         {stats['invalid']:,} ({invalid_pct:.1f}%)")
            print(f"Total time:        {elapsed:.2f}s")
            print(f"Requests/second:   {rps:.1f}")
            if intervals:
                print(f"Interval avg:      {avg_interval:.2f}ms")
                print(f"Interval range:    {min_interval:.2f}ms - {max_interval:.2f}ms")
            if stats["errors"]:
                print("\nError breakdown:")
                for err, count in sorted(stats["errors"].items(), key=lambda x: -x[1])[:10]:
                    print(f"  {err}: {count}")
            print("=" * 70)
        else:
            print(
                f"[{datetime.now().strftime('%H:%M:%S')}] "
                f"Total: {stats['total']:,} | "
                f"Valid: {stats['valid']} ({valid_pct:.0f}%) | "
                f"Invalid: {stats['invalid']} ({invalid_pct:.0f}%) | "
                f"RPS: {rps:.1f} | "
                f"Interval: {avg_interval:.1f}ms"
            )


class RawTCPServer:
    """Raw TCP server to catch ALL requests including malformed ones"""

    def __init__(self, port):
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("0.0.0.0", port))
        self.sock.listen(128)
        self.running = True

    def serve_forever(self):
        while self.running:
            try:
                self.sock.settimeout(1.0)
                try:
                    conn, addr = self.sock.accept()
                except socket.timeout:
                    continue

                # Handle in thread for concurrency
                t = threading.Thread(target=self.handle_client, args=(conn,))
                t.daemon = True
                t.start()
            except Exception:
                if self.running:
                    continue

    def handle_client(self, conn):
        global stats

        now = time.time()
        is_valid = False
        error_type = None

        try:
            conn.settimeout(2.0)

            # Read request data
            data = b""
            try:
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    # Check for end of headers
                    if b"\r\n\r\n" in data or b"\n\n" in data:
                        break
                    if len(data) > 65536:  # Limit
                        break
            except socket.timeout:
                pass

            if data:
                # Parse and validate HTTP request
                is_valid, error_type = self.validate_http(data)

                # Send response
                if is_valid:
                    response = (
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
                    )
                else:
                    response = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\nConnection: close\r\n\r\nBad Request"

                try:
                    conn.sendall(response)
                except Exception:
                    pass

        except Exception as e:
            error_type = type(e).__name__
        finally:
            try:
                conn.close()
            except Exception:
                pass

        # Update stats
        with stats_lock:
            if stats["start_time"] is None:
                stats["start_time"] = now

            stats["total"] += 1
            if is_valid:
                stats["valid"] += 1
            else:
                stats["invalid"] += 1
                if error_type:
                    stats["errors"][error_type] = stats["errors"].get(error_type, 0) + 1

            # Track intervals
            if stats["last_time"] is not None:
                interval = (now - stats["last_time"]) * 1000
                stats["intervals"].append(interval)
                if len(stats["intervals"]) > 100:
                    stats["intervals"].pop(0)
            stats["last_time"] = now

            # Print every 100 requests
            if stats["total"] % 100 == 0:
                print_stats()

    def validate_http(self, data):
        """Validate HTTP request, return (is_valid, error_type)"""
        try:
            # Must have some data
            if not data or len(data) < 10:
                return False, "TooShort"

            # Try to decode as text
            try:
                text = data.decode("utf-8", errors="replace")
            except Exception:
                return False, "DecodeError"

            # Split into lines
            if "\r\n" in text:
                lines = text.split("\r\n")
            elif "\n" in text:
                lines = text.split("\n")
            else:
                return False, "NoNewline"

            if not lines or not lines[0]:
                return False, "EmptyRequest"

            # Parse request line
            request_line = lines[0]
            parts = request_line.split(" ")

            if len(parts) < 2:
                return False, "BadRequestLine"

            method = parts[0]

            # Valid HTTP methods
            valid_methods = {
                "GET",
                "POST",
                "PUT",
                "DELETE",
                "HEAD",
                "OPTIONS",
                "PATCH",
                "CONNECT",
                "TRACE",
                "SEARCH",
                "PROPFIND",
                "PROPPATCH",
                "MKCOL",
                "COPY",
                "MOVE",
                "LOCK",
                "UNLOCK",
            }

            if method not in valid_methods:
                return False, f"BadMethod:{method[:20]}"

            # Check for HTTP version (optional for HTTP/0.9)
            if len(parts) >= 3:
                version = parts[-1]
                if not version.startswith("HTTP/"):
                    return False, "BadVersion"

            # Check for Host header (required in HTTP/1.1)
            has_host = any(line.lower().startswith("host:") for line in lines[1:])
            if len(parts) >= 3 and "HTTP/1.1" in parts[-1] and not has_host:
                return False, "NoHost"

            return True, None

        except Exception as e:
            return False, type(e).__name__

    def shutdown(self):
        self.running = False
        self.sock.close()


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080

    print("Benchmark HTTP Server (Raw TCP)")
    print("=" * 70)
    print(f"Listening on: http://0.0.0.0:{port}")
    print("")
    print("To benchmark fuzzer:")
    print(f"  oida fuzz http 127.0.0.1 -p {port} -v")
    print("")
    print("Stats printed every 100 requests:")
    print("  - Valid:   well-formed HTTP requests")
    print("  - Invalid: malformed/fuzzed requests")
    print("  - RPS:     requests per second")
    print("  - Interval: time between requests (ms)")
    print("")
    print("Press Ctrl+C to stop and see final stats")
    print("=" * 70)
    print()

    server = RawTCPServer(port)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
        print_stats(final=True)


if __name__ == "__main__":
    main()
