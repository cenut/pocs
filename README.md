# PHP2Shell trigger scripts (online target mode)

Two bounded request-trigger harnesses for the PHP advisory cases. They run directly from your machine against a **live/online URL** you own or are explicitly authorized to test — no Docker required anymore; the local Compose lab nodes were removed.

## Advisory trigger scripts

```sh
python3 trigger_cve_2026_109618.py --url https://target.com/
python3 trigger_cve_2026_109619.py --url https://target.com/ \
  --health-path /control/health.php --marker "HEALTHY 8.5.4"
```

| Script | What it sends | What you should observe | Limit |
| --- | --- | --- | --- |
| `trigger_cve_2026_109618.py` | One bounded multipart POST sized to exhaust PHP's `memory_limit` during parsing (default calibrated for 16M limit / 8M post_max_size) | HTTP 500 / memory-exhaustion response, then the site answers the follow-up health check | Trigger only; no corruption or RCE claim |
| `trigger_cve_2026_109619.py` | Fatal-error producer request followed by an early-diagnostic consumer request | Consumer connection may drop (worker abort); server recovers on the next request | Trigger only; needs the producer/consumer endpoints to exist on the target |

Useful flags (both scripts): `--post-path`/`--producer-path`/`--consumer-path`/`--health-path` to match the target's real endpoints, `--value-size` to tune payload size to the target's PHP limits, `--baseline-marker`/`--marker` to refuse firing at the wrong host, `--insecure` for self-signed TLS, `--timeout`.

## Safety notes

- These requests are **DoS-class probes** (memory exhaustion / worker abort). Run them only against hosts you own or have written authorization to test, and do not loop them.
- The scripts keep a body-size cap (`MAX_BODY`) and make no attempt at memory corruption, use-after-free shaping, or code execution.
- On a generic online target the default endpoint paths (`/producer/fatal.php`, `/consumer/index.php`, `/control/health.php`) came from the removed lab layout — they will 404 unless the target actually exposes them. Set `--marker`/`--baseline-marker` so the script aborts before triggering if the host is not the intended one.

## ASLR/RCE PoC lab

The disposable Docker lab for the upstream 9bie ASLR/RCE PoC remains available under `aslr-lab/` (binds only to `127.0.0.1:8089`):

Requirements: Docker Engine or Docker Desktop with Docker Compose v2, Git, Python 3.10 or newer, `curl`, and network access for the first image and submodule downloads. On Apple Silicon, Docker uses emulation for the `linux/amd64` target.

Clone the repository and its upstream PoC submodule:

```sh
git clone --recurse-submodules https://github.com/jf0x3f/php2shell-pocs.git
cd php2shell-pocs
```

If you already cloned without submodules, initialize them from the repository root:

```sh
git submodule update --init --recursive
```

Run the lab from the repository root:

```sh
./aslr-lab/run-aslr-lab.sh
```

The script starts the target, runs the PoC's built-in `id>/out/p1` proof command, then removes the temporary container and network. Success prints a line like:

```text
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The proof and detected offsets remain in `aslr-lab/aslr-out/` and are ignored by Git. The screenshot shows a successful run and cleanup.

![Successful local ASLR lab run showing the heap and libphp leaks, www-data proof, and container cleanup](aslr-lab/screenshots/aslr-lab-success.png)

## References

- [PHP security advisory: CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [PHP security advisory: CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [9bie's ASLR/RCE PoC and documentation](https://github.com/9bie/php2shell-bypass-aslr-exp)
- [Wiz Research: PHP2Shell technical write-up](https://www.wiz.io/blog/php2shell-php-rce)
