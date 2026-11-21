#!/usr/bin/env python3
"""Check ordinary TLS handshakes for observed hosts from this machine/network.

Any hostname with at least one verified TLS handshake is not automatically
classified as affected. All current A/AAAA answers must fail every retry before
a host is written by --write-affected. DNS failures are UNKNOWN.
"""
from __future__ import annotations

import argparse
import socket
import ssl
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_filter import CONNECT_TIMEOUT, normalize_hostname

ATTEMPTS_PER_ADDRESS = 3
MAX_ADDRESSES_PER_HOST = 12


def resolve(hostname: str) -> list[tuple[int, int, int, tuple]]:
    try:
        answers = socket.getaddrinfo(hostname, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except OSError:
        return []
    unique = {(item[0], item[1], item[2], item[4]) for item in answers}
    return sorted(unique, key=lambda item: (item[0], str(item[3])))[:MAX_ADDRESSES_PER_HOST]


def handshake(
    sockaddr: tuple, family: int, socktype: int, proto: int, hostname: str
) -> tuple[bool, str]:
    raw = socket.socket(family, socktype, proto)
    raw.settimeout(CONNECT_TIMEOUT)
    try:
        raw.connect(sockaddr)
        context = ssl.create_default_context()
        with context.wrap_socket(raw, server_hostname=hostname):
            return True, "verified TLS handshake"
    except (OSError, ssl.SSLError) as exc:
        return False, f"{type(exc).__name__}: {exc}"
    finally:
        raw.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path,
                        help="observed-hosts file, one hostname per line")
    parser.add_argument("--write-affected", type=Path,
                        help="write only hosts whose resolved A/AAAA addresses all fail every retry")
    args = parser.parse_args()

    statuses: list[tuple[str, str]] = []
    for line_no, raw in enumerate(args.input.read_text(encoding="utf-8").splitlines(), 1):
        value = raw.split("#", 1)[0].strip()
        if not value:
            continue
        try:
            host = normalize_hostname(value)
        except ValueError as exc:
            parser.error(f"{args.input}:{line_no}: {exc}")

        addresses = resolve(host)
        if not addresses:
            print(f"UNKNOWN {host}: no current A/AAAA addresses", file=sys.stderr)
            statuses.append((host, "UNKNOWN"))
            continue

        passed = 0
        failed = 0
        for family, socktype, proto, sockaddr in addresses:
            address = sockaddr[0]
            address_ok = False
            for attempt in range(1, ATTEMPTS_PER_ADDRESS + 1):
                ok, detail = handshake(sockaddr, family, socktype, proto, host)
                print(f"  {host} -> {address} attempt {attempt}/{ATTEMPTS_PER_ADDRESS}: {detail}", file=sys.stderr)
                if ok:
                    address_ok = True
                    break
            if address_ok:
                passed += 1
            else:
                failed += 1

        if passed and failed:
            status = "PARTIAL"
        elif passed:
            status = "OK"
        else:
            status = "AFFECTED"
        print(f"{status} {host}: {passed} address(es) passed, {failed} failed", file=sys.stderr)
        statuses.append((host, status))

    if args.write_affected:
        affected = [host for host, status in statuses if status == "AFFECTED"]
        text = "# Generated locally; review before publishing.\n"
        text += "".join(f"{host}\n" for host in affected)
        args.write_affected.parent.mkdir(parents=True, exist_ok=True)
        args.write_affected.write_text(text, encoding="utf-8")
        print(f"Wrote {len(affected)} affected hostname(s) to {args.write_affected}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
