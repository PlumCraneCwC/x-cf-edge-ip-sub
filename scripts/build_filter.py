#!/usr/bin/env python3
"""Build exact-host, IPv4-only AdGuard Home rules for confirmed affected hosts.

The target list is intentionally explicit: GitHub's network cannot determine
which hosts fail TLS on the user's client network. Every listed host must have
an address pinned in ``static-ips.txt``; nothing is guessed from DNS, so an
unpinned host fails the build instead of shipping an unverified rule.
"""
from __future__ import annotations

import argparse
import ipaddress
import os
import re
import socket
import ssl
import statistics
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Mapping

DOMAIN = "x.com"  # Legacy test/default; production targets come from targets.txt.
PORT = 443
ATTEMPTS = 3
MIN_SUCCESSES = 2
MAX_CANDIDATES = 12
CONNECT_TIMEOUT = 4.0
IO_TIMEOUT = 10.0
DEFAULT_TARGETS = Path(__file__).resolve().parents[1] / "targets.txt"
STATIC_IPS_FILE = Path(__file__).resolve().parents[1] / "static-ips.txt"


@dataclass(frozen=True)
class Probe:
    ok: bool
    elapsed: float | None = None
    status: int | None = None
    error: str | None = None


def normalize_hostname(hostname: str) -> str:
    """Validate and normalize one exact DNS hostname (no wildcard patterns)."""
    value = hostname.strip().rstrip(".").lower()
    if not value or "*" in value or "/" in value or "|" in value:
        raise ValueError(f"not an exact hostname: {hostname!r}")
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"invalid internationalized hostname: {hostname!r}") from exc
    if len(value) > 253:
        raise ValueError(f"hostname is too long: {hostname!r}")
    labels = value.split(".")
    if any(
        not label
        or len(label) > 63
        or re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) is None
        for label in labels
    ):
        raise ValueError(f"invalid DNS hostname: {hostname!r}")
    return value


WILDCARD_TARGET_RE = re.compile(r"^\|\|([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)\^$")


def split_target(target: str) -> tuple[str, str]:
    """Return (kind, hostname); kind is 'exact' or 'wildcard'.

    A wildcard target is written as ``||x.com^`` and covers the apex domain plus
    every subdomain, which is what AdGuard Home's ``||domain^`` syntax matches.
    """
    match = WILDCARD_TARGET_RE.fullmatch(target)
    if match:
        return "wildcard", normalize_hostname(match.group(1))
    return "exact", normalize_hostname(target)


def read_targets(path: Path) -> list[str]:
    """Read an explicit exact-host allowlist, ignoring blank/comment lines."""
    targets: list[str] = []
    seen: set[str] = set()
    for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        value = raw.split("#", 1)[0].strip()
        if not value:
            continue
        try:
            kind, host = split_target(value)
        except ValueError as exc:
            raise ValueError(f"{path}:{line_no}: {exc}") from exc
        key = f"||{host}^" if kind == "wildcard" else host
        if key not in seen:
            targets.append(key)
            seen.add(key)
    if not targets:
        raise RuntimeError(f"no exact hostnames configured in {path}")
    return targets


def read_static_ips(path: Path) -> dict[str, str]:
    """Return explicit "hostname ip" pins, keyed by normalized hostname."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return {}
    pins: dict[str, str] = {}
    for line_no, line in enumerate(lines, 1):
        raw = line.split("#", 1)[0].strip()
        if not raw:
            continue
        parts = raw.split()
        if len(parts) != 2:
            raise ValueError(f"{path}:{line_no}: expected 'hostname ip', got {raw!r}")
        host = normalize_hostname(parts[0])
        parsed = ipaddress.ip_address(parts[1])
        if parsed.version != 4 or not parsed.is_global:
            raise ValueError(f"{path}:{line_no}: not a public IPv4 address: {parts[1]!r}")
        pins[host] = str(parsed)
    return pins


def _read_headers(sock: ssl.SSLSocket, limit: int = 16_384) -> bytes:
    data = bytearray()
    while b"\r\n\r\n" not in data and len(data) < limit:
        chunk = sock.recv(min(4096, limit - len(data)))
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def probe_ipv4(ip: str, hostname: str = DOMAIN, *, accept_any_http: bool = False) -> Probe:
    """Probe a candidate IP with hostname-preserving TLS/SNI and HTTP/1.1.

    accept_any_http relaxes the status check to "the server answered with a
    valid HTTP status line". Needed for static pins where the origin really
    does answer 4xx on "/" (e.g. pbs.twimg.com returns 400 by design) but the
    address is still the right edge for that SNI.
    """
    hostname = normalize_hostname(hostname)
    started = time.monotonic()
    raw: socket.socket | None = None
    try:
        parsed = ipaddress.ip_address(ip)
        if parsed.version != 4 or not parsed.is_global:
            return Probe(False, error="candidate is not a public IPv4 address")

        raw = socket.create_connection((ip, PORT), timeout=CONNECT_TIMEOUT)
        raw.settimeout(IO_TIMEOUT)
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.set_alpn_protocols(["http/1.1"])

        with context.wrap_socket(raw, server_hostname=hostname) as tls:
            raw = None  # wrapped socket owns the file descriptor
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {hostname}\r\n"
                "User-Agent: xcom-adguard-route-check/1.0\r\n"
                "Accept: */*\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
            tls.sendall(request)
            response = _read_headers(tls)

        first_line = response.split(b"\r\n", 1)[0].decode("ascii", "replace")
        fields = first_line.split()
        if len(fields) < 2 or not fields[0].startswith("HTTP/") or not fields[1].isdigit():
            return Probe(False, elapsed=time.monotonic() - started,
                         error=f"invalid HTTP status line: {first_line[:120]!r}")
        status = int(fields[1])
        elapsed = time.monotonic() - started
        if 200 <= status < 400:
            return Probe(True, elapsed=elapsed, status=status)
        if accept_any_http:
            return Probe(True, elapsed=elapsed, status=status)
        return Probe(False, elapsed=elapsed, status=status,
                     error=f"HTTP status {status} is outside the accepted 2xx/3xx range")
    except (OSError, ssl.SSLError, ValueError) as exc:
        return Probe(False, elapsed=time.monotonic() - started,
                     error=f"{type(exc).__name__}: {exc}")
    finally:
        if raw is not None:
            try:
                raw.close()
            except OSError:
                pass


def choose_candidate(
    candidates: Iterable[str],
    probe_fn: Callable[[str], Probe] = probe_ipv4,
    attempts: int = ATTEMPTS,
    min_successes: int = MIN_SUCCESSES,
) -> tuple[str, dict[str, list[Probe]]]:
    """Select by success count first, then median successful end-to-end latency."""
    unique = sorted({str(ipaddress.ip_address(ip)) for ip in candidates})[:MAX_CANDIDATES]
    if not unique:
        raise RuntimeError("no candidate addresses to test")
    if attempts < 1 or min_successes < 1 or min_successes > attempts:
        raise ValueError("require 1 <= min_successes <= attempts")

    results: dict[str, list[Probe]] = {}
    eligible: list[tuple[int, float, str]] = []
    for ip in unique:
        probes: list[Probe] = []
        for attempt in range(attempts):
            probes.append(probe_fn(ip))
            if attempt + 1 < attempts:
                time.sleep(0.25)
        results[ip] = probes
        good = [p for p in probes if p.ok and p.elapsed is not None]
        summary = (
            f"{ip}: {len(good)}/{attempts} successful"
            + (f", median={statistics.median(p.elapsed for p in good):.3f}s" if good else "")
        )
        if not good:
            reason = next((p.error for p in probes if p.error), "no successful response")
            summary += f", sample failure={reason[:180]}"
        print(summary, file=sys.stderr)
        if len(good) >= min_successes:
            eligible.append((-len(good), statistics.median(p.elapsed for p in good), ip))

    if not eligible:
        raise RuntimeError(
            f"no candidate address passed at least {min_successes}/{attempts} "
            f"TLS/HTTP probes; refusing to publish an unverified rule"
        )
    eligible.sort()
    return eligible[0][2], results


def render_rules(
    addresses: Mapping[str, str], generated_at: datetime | None = None
) -> str:
    """Render exact-host A-only DNS rewrites for the supplied affected hosts."""
    if not addresses:
        raise ValueError("at least one affected hostname is required")
    stamp = (generated_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    lines = [
        "! Title: Confirmed affected X-related hosts (automatically TLS/HTTP verified)",
        "! Description: A queries rewritten to reachable IPv4 addresses; AAAA",
        "! queries answered NXDOMAIN so clients stop preferring dead IPv6 paths.",
        f"! Generated: {stamp.isoformat(timespec='seconds')}",
    ]
    for raw_host, ip in addresses.items():
        kind, host = split_target(raw_host)
        parsed = ipaddress.ip_address(ip)
        if parsed.version != 4 or not parsed.is_global:
            raise ValueError(f"only public IPv4 addresses can be published: {ip}")
        if kind == "wildcard":
            prefix = f"||{host}^"
        else:
            prefix = f"|{host}|"
        lines.append(f"{prefix}$dnstype=A,dnsrewrite=NOERROR;A;{parsed}")
        lines.append(f"{prefix}$dnstype=AAAA,dnsrewrite=NXDOMAIN")
    return "\n".join(lines) + "\n"


def render_rule(ip: str, generated_at: datetime | None = None) -> str:
    """Backward-compatible single-host renderer used by existing callers/tests."""
    return render_rules({DOMAIN: ip}, generated_at)


def atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", dir=path.parent,
            prefix=f".{path.name}.", suffix=".tmp", delete=False,
        ) as output:
            temp_name = output.name
            output.write(text)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp_name, path)
    finally:
        if temp_name and os.path.exists(temp_name):
            os.unlink(temp_name)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="output filter-list path")
    parser.add_argument("--targets", type=Path, default=DEFAULT_TARGETS,
                        help=f"explicit exact-host affected list (default: {DEFAULT_TARGETS})")
    parser.add_argument("--trust-static-pins", action="store_true",
                        help="accept static-ips.txt entries without probing them "
                             "(probe bursts can trip the edge's rate limiting)")
    args = parser.parse_args()

    targets = read_targets(args.targets)
    static_ips = read_static_ips(STATIC_IPS_FILE)
    if static_ips:
        print(f"Static host pins: {', '.join(f'{k}->{v}' for k, v in static_ips.items())}", file=sys.stderr)
    print(f"Explicit affected hosts: {', '.join(targets)}", file=sys.stderr)

    selected: dict[str, str] = {}
    for target in targets:
        kind, host = split_target(target)
        if host in static_ips:
            pinned = static_ips[host]
            if args.trust_static_pins:
                selected[target] = pinned
                print(f"Selected {host} -> {pinned} (static pin, not probed)", file=sys.stderr)
                continue
            probes = []
            for _ in range(ATTEMPTS):
                probes.append(probe_ipv4(pinned, hostname=host, accept_any_http=True))
                time.sleep(0.4)  # Fastly resets bursts of back-to-back handshakes
            if sum(1 for probe in probes if probe.ok) < MIN_SUCCESSES:
                raise RuntimeError(
                    f"static pin {pinned} for {host} failed the probe from this runner; "
                    "refusing to publish an unverified rule"
                )
            selected[target] = pinned
            print(f"Selected {host} -> {pinned} (static pin)", file=sys.stderr)
            continue
        raise RuntimeError(
            f"{host} has no entry in static-ips.txt; refusing to publish an unverified rule"
        )

    atomic_write(args.output, render_rules(selected))
    print(f"Wrote {len(selected)} exact-host rules to {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
