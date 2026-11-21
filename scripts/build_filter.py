#!/usr/bin/env python3
"""Build exact-host, IPv4-only AdGuard Home rules for confirmed affected hosts.

The target list is intentionally explicit: GitHub's network cannot determine
which hosts fail TLS on the user's client network. For each listed host, the
current public A records of jsdelivr.com are tested with that host as TLS SNI
and HTTP Host. Only listed hosts can appear in the generated feed.
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
CANDIDATE_DOMAIN = "jsdelivr.com"
PORT = 443
ATTEMPTS = 3
MIN_SUCCESSES = 2
MAX_CANDIDATES = 12
CONNECT_TIMEOUT = 4.0
IO_TIMEOUT = 5.0
DEFAULT_TARGETS = Path(__file__).resolve().parents[1] / "targets.txt"
# Optional operator-provided IP that this workflow should prefer for every
# affected host, as long as it still passes the probes from the runner. The
# client-side helper (scripts/client_verify.py) rewrites this file after
# measuring which Cloudflare anycast addresses are reachable from the LAN.
PREFERRED_IP_FILE = Path(__file__).resolve().parents[1] / "preferred-ip.txt"
# Optional per-host pins for hosts that do NOT sit on a Cloudflare edge (for
# example pbs.twimg.com, which is Fastly). One "hostname ip" pair per line.
# A pinned host skips the jsdelivr candidate search entirely and must still
# pass the probe on the pinned address from the runner, otherwise the build
# fails closed instead of publishing an unverified rewrite.
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


def resolve_ipv4(hostname: str = CANDIDATE_DOMAIN) -> list[str]:
    """Return unique public IPv4 addresses resolved for the candidate host."""
    answers = socket.getaddrinfo(hostname, PORT, socket.AF_INET, socket.SOCK_STREAM)
    candidates: set[str] = set()
    for answer in answers:
        address = answer[4][0]
        parsed = ipaddress.ip_address(address)
        if parsed.version == 4 and parsed.is_global:
            candidates.add(str(parsed))
    return sorted(candidates)[:MAX_CANDIDATES]


def read_preferred_ips(path: Path) -> list[str]:
    """Return operator-preferred IPv4 candidates, in file order, if any exist.

    Each non-comment line is one address; the first address that passes the
    probes for a host wins, so the list doubles as a fallback chain.
    """
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return []
    result: list[str] = []
    for line in lines:
        raw = line.split("#", 1)[0].strip()
        if not raw:
            continue
        parsed = ipaddress.ip_address(raw)
        if parsed.version != 4 or not parsed.is_global:
            raise ValueError(f"{path} does not contain a public IPv4 address: {raw!r}")
        result.append(str(parsed))
    return result


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
        raise RuntimeError(f"DNS returned no public IPv4 addresses for {CANDIDATE_DOMAIN}")
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
            f"no {CANDIDATE_DOMAIN} address passed at least {min_successes}/{attempts} "
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
        "! Description: A queries only; no AAAA rewrite. Rules follow targets.txt.",
        f"! Generated: {stamp.isoformat(timespec='seconds')}",
    ]
    for raw_host, ip in addresses.items():
        kind, host = split_target(raw_host)
        parsed = ipaddress.ip_address(ip)
        if parsed.version != 4 or not parsed.is_global:
            raise ValueError(f"only public IPv4 addresses can be published: {ip}")
        if kind == "wildcard":
            lines.append(f"||{host}^$dnstype=A,dnsrewrite=NOERROR;A;{parsed}")
        else:
            lines.append(f"|{host}|$dnstype=A,dnsrewrite=NOERROR;A;{parsed}")
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
    args = parser.parse_args()

    targets = read_targets(args.targets)
    try:
        candidates = resolve_ipv4()
    except OSError as exc:
        print(f"warning: could not resolve {CANDIDATE_DOMAIN}: {exc}", file=sys.stderr)
        candidates = []
    static_ips = read_static_ips(STATIC_IPS_FILE)
    if static_ips:
        print(f"Static host pins: {', '.join(f'{k}->{v}' for k, v in static_ips.items())}", file=sys.stderr)
    preferred_ips = read_preferred_ips(PREFERRED_IP_FILE)
    if preferred_ips:
        print(f"Operator-preferred candidate IPs: {', '.join(preferred_ips)}", file=sys.stderr)
    print(f"Explicit affected hosts: {', '.join(targets)}", file=sys.stderr)
    print(f"Resolved {CANDIDATE_DOMAIN} IPv4 candidates: {', '.join(candidates)}", file=sys.stderr)

    selected: dict[str, str] = {}
    for target in targets:
        kind, host = split_target(target)
        placed = False
        if host in static_ips:
            pinned = static_ips[host]
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
        for preferred in preferred_ips:
            probes = [probe_ipv4(preferred, hostname=host) for _ in range(ATTEMPTS)]
            if sum(1 for probe in probes if probe.ok) >= MIN_SUCCESSES:
                selected[target] = preferred
                print(f"Selected {host} -> {preferred} (preferred)", file=sys.stderr)
                placed = True
                break
            print(f"Preferred {preferred} did not pass for {host}", file=sys.stderr)
        if placed:
            continue
        print(f"Testing jsdelivr candidate IPs with SNI/Host {host}", file=sys.stderr)
        ip, _ = choose_candidate(
            candidates,
            probe_fn=lambda candidate, target=host: probe_ipv4(candidate, hostname=target),
        )
        selected[target] = ip
        print(f"Selected {host} -> {ip}", file=sys.stderr)

    atomic_write(args.output, render_rules(selected))
    print(f"Wrote {len(selected)} exact-host rules to {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
