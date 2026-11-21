from datetime import datetime, timezone
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import build_filter


class BuildFilterTests(unittest.TestCase):
    def test_render_is_exact_host_a_only_rule(self):
        rendered = build_filter.render_rule(
            "104.21.8.91", datetime(2026, 11, 22, 0, 0, tzinfo=timezone.utc)
        )
        self.assertIn("|x.com|$dnstype=A,dnsrewrite=NOERROR;A;104.21.8.91", rendered)
        self.assertNotIn("||x.com^", rendered)
        self.assertNotIn("dnstype=AAAA", rendered)

    def test_render_rules_only_contains_explicit_hosts(self):
        rendered = build_filter.render_rules({
            "api.x.com": "104.21.8.91",
            "pbs.twimg.com": "172.67.130.104",
        })
        self.assertIn("|api.x.com|$dnstype=A,dnsrewrite=NOERROR;A;104.21.8.91", rendered)
        self.assertIn("|pbs.twimg.com|$dnstype=A,dnsrewrite=NOERROR;A;172.67.130.104", rendered)
        self.assertNotIn("||x.com^", rendered)
        self.assertNotIn("*.x.com", rendered)

    def test_wildcards_and_bad_hostnames_are_rejected(self):
        for host in ("*.x.com", "||x.com^", "https://x.com", "bad..x.com"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                build_filter.normalize_hostname(host)

    def test_render_rejects_non_public_or_ipv6(self):
        for address in ("127.0.0.1", "10.0.0.1", "2001:db8::1"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                build_filter.render_rule(address)

    def test_choose_prefers_more_successes_then_latency(self):
        data = {
            "104.21.8.91": [
                build_filter.Probe(True, 0.50, 200),
                build_filter.Probe(True, 0.52, 200),
                build_filter.Probe(False, 0.8, 503, "HTTP status 503"),
            ],
            "172.67.130.104": [
                build_filter.Probe(True, 0.7, 200),
                build_filter.Probe(True, 0.6, 200),
                build_filter.Probe(True, 0.8, 200),
            ],
        }
        selected, _ = build_filter.choose_candidate(
            data,
            probe_fn=lambda ip: data[ip].pop(0),
            attempts=3,
            min_successes=2,
        )
        self.assertEqual(selected, "172.67.130.104")

    def test_no_stable_candidate_fails_closed(self):
        selected = [build_filter.Probe(False, error="timeout")]
        with self.assertRaisesRegex(RuntimeError, "refusing to publish"):
            build_filter.choose_candidate(
                ["104.21.8.91"], probe_fn=lambda _ip: selected[0], attempts=3, min_successes=2
            )

    def test_reject_invalid_candidate_address(self):
        with self.assertRaises(ValueError):
            build_filter.choose_candidate(["not-an-ip"], probe_fn=lambda _ip: None)


if __name__ == "__main__":
    unittest.main()
