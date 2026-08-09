"""TCP ping prefilter tests.

Standalone: uses real loopback sockets for the alive/dead path and a stubbed
probe for the pure filtering logic. Reuses the stub installers + v2rayChecker
loader from test_issue14_generators.
"""
import asyncio
import socket
import unittest

from test_issue14_generators import _install_rich_stub, _install_psutil_stub, _load_v2ray_checker

_install_rich_stub()
_install_psutil_stub()


_UUID = "a3f5b8a1-2c3d-4e5f-8a9b-0c1d2e3f4a5b"
_PBK = "cHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHA"


def _open_listener():
    """Listening loopback socket -> (sock, port). Accepts TCP, answers nothing."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(64)
    return sock, sock.getsockname()[1]


def _closed_port():
    """Port number nothing listens on (bind, read port, close)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class TcpPingEndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_v2ray_checker()

    def test_vless_endpoint_is_tcp(self):
        url = f"vless://{_UUID}@example.com:443?security=reality&pbk={_PBK}&sni=a.example.com#tag"
        self.assertEqual(self.mod.tcp_ping_endpoint(url), ("example.com", 443, False))

    def test_hysteria2_endpoint_is_flagged_udp(self):
        url = "hysteria2://pass@example.com:8443?sni=example.com"
        endpoint = self.mod.tcp_ping_endpoint(url)
        self.assertIsNotNone(endpoint)
        self.assertEqual(endpoint[:2], ("example.com", 8443))
        self.assertTrue(endpoint[2], "hysteria2 must be flagged as UDP-only")

    def test_tuic_endpoint_is_flagged_udp(self):
        url = f"tuic://{_UUID}:password@example.com:2053?sni=example.com"
        endpoint = self.mod.tcp_ping_endpoint(url)
        self.assertIsNotNone(endpoint)
        self.assertTrue(endpoint[2], "tuic must be flagged as UDP-only")

    def test_native_mihomo_dict_endpoint(self):
        native = {"_native_mihomo": True, "type": "vmess", "server": "10.0.0.1", "port": 8080, "name": "x"}
        self.assertEqual(self.mod.tcp_ping_endpoint(native), ("10.0.0.1", 8080, False))

    def test_unparseable_link_has_no_endpoint(self):
        self.assertIsNone(self.mod.tcp_ping_endpoint("weird://nothing-here"))
        self.assertIsNone(self.mod.tcp_ping_endpoint(""))


class TcpPingOptionsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_v2ray_checker()

    def test_defaults_from_config(self):
        opts = self.mod.build_tcp_ping_options(None, {})
        self.assertTrue(opts["enabled"])
        self.assertGreater(opts["timeout"], 0)
        self.assertGreaterEqual(opts["concurrency"], 1)

    def test_cli_overrides_config(self):
        args = type("A", (), {
            "tcp_ping": False, "tcp_ping_timeout": 7.5, "tcp_ping_concurrency": 42,
            "tcp_ping_retries": 3, "tcp_ping_max_ms": 250,
        })()
        opts = self.mod.build_tcp_ping_options(args, {"tcp_ping": {"enabled": True, "timeout": 1.0}})
        self.assertFalse(opts["enabled"])
        self.assertEqual(opts["timeout"], 7.5)
        self.assertEqual(opts["concurrency"], 42)
        self.assertEqual(opts["retries"], 3)
        self.assertEqual(opts["max_latency_ms"], 250)

    def test_garbage_values_are_clamped(self):
        cfg = {"tcp_ping": {
            "enabled": True, "timeout": -5, "concurrency": 999999,
            "retries": 99, "max_latency_ms": -1, "max_ips_per_host": 0,
        }}
        opts = self.mod.build_tcp_ping_options(None, cfg)
        self.assertGreaterEqual(opts["timeout"], 0.1)
        self.assertLessEqual(opts["concurrency"], 5000)
        self.assertLessEqual(opts["retries"], 5)
        self.assertEqual(opts["max_latency_ms"], 0)
        self.assertGreaterEqual(opts["max_ips_per_host"], 1)

    def test_broken_types_fall_back_to_defaults(self):
        opts = self.mod.build_tcp_ping_options(None, {"tcp_ping": {"timeout": "nope", "concurrency": None}})
        self.assertGreater(opts["timeout"], 0)
        self.assertGreaterEqual(opts["concurrency"], 1)


class TcpPingFilterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_v2ray_checker()

    def setUp(self):
        self.opts = self.mod.build_tcp_ping_options(None, {})
        # Windows refuses a closed loopback port only after ~2s (ConnectEx SYN retry).
        self.opts.update({"timeout": 6.0, "concurrency": 8, "retries": 0, "report_file": ""})

    def _vless(self, port):
        return f"vless://{_UUID}@127.0.0.1:{port}?security=none&sni=a.example.com"

    def test_alive_kept_dead_dropped(self):
        listener, alive_port = _open_listener()
        self.addCleanup(listener.close)
        dead_port = _closed_port()

        alive, dead = self._vless(alive_port), self._vless(dead_port)
        kept, stats = self.mod.tcp_ping_filter([alive, dead], self.opts, show_progress=False)

        self.assertEqual(kept, [alive])
        self.assertEqual(stats["alive"], 1)
        self.assertEqual(stats["dead"], 1)
        self.assertEqual(stats["probed"], 2)

    def test_input_list_is_not_mutated_and_order_kept(self):
        listener, alive_port = _open_listener()
        self.addCleanup(listener.close)
        second, alive_port2 = _open_listener()
        self.addCleanup(second.close)

        source = [self._vless(alive_port), self._vless(_closed_port()), self._vless(alive_port2)]
        snapshot = list(source)
        kept, _ = self.mod.tcp_ping_filter(source, self.opts, show_progress=False)

        self.assertEqual(source, snapshot, "input list must not be mutated")
        self.assertEqual(kept, [source[0], source[2]], "order must be preserved")

    def test_udp_protocol_passes_through_untouched(self):
        # Dead port, but hysteria2 is UDP-only: TCP probe must not judge it.
        hy2 = f"hysteria2://pass@127.0.0.1:{_closed_port()}?sni=a.example.com"
        kept, stats = self.mod.tcp_ping_filter([hy2], self.opts, show_progress=False)

        self.assertEqual(kept, [hy2])
        self.assertEqual(stats["skipped_udp"], 1)
        self.assertEqual(stats["probed"], 0)

    def test_udp_protocol_is_probed_when_skip_udp_off(self):
        self.opts["skip_udp"] = False
        hy2 = f"hysteria2://pass@127.0.0.1:{_closed_port()}?sni=a.example.com"
        kept, stats = self.mod.tcp_ping_filter([hy2], self.opts, show_progress=False)

        self.assertEqual(kept, [])
        self.assertEqual(stats["skipped_udp"], 0)
        self.assertEqual(stats["dead"], 1)

    def test_unparseable_link_survives_the_prefilter(self):
        # No host:port to probe -> the prefilter must not silently eat it.
        junk = "weird://not-a-proxy"
        kept, stats = self.mod.tcp_ping_filter([junk], self.opts, show_progress=False)

        self.assertEqual(kept, [junk])
        self.assertEqual(stats["skipped_unknown"], 1)

    def test_disabled_filter_is_a_passthrough(self):
        self.opts["enabled"] = False
        source = [self._vless(_closed_port())]
        kept, stats = self.mod.tcp_ping_filter(source, self.opts, show_progress=False)

        self.assertEqual(kept, source)
        self.assertEqual(stats["probed"], 0)

    def test_max_latency_threshold_drops_slow_endpoints(self):
        # Stub the probe: deterministic latencies beat timing-dependent sockets.
        latencies = {}

        async def fake_probe(host, port, opts, dns_cache):
            return latencies[port], "ok"

        fast_port, slow_port = 11111, 22222
        latencies[fast_port] = 50.0
        latencies[slow_port] = 900.0

        original = self.mod._tcp_ping_probe
        self.mod._tcp_ping_probe = fake_probe
        self.addCleanup(setattr, self.mod, "_tcp_ping_probe", original)

        self.opts["max_latency_ms"] = 300
        fast, slow = self._vless(fast_port), self._vless(slow_port)
        kept, stats = self.mod.tcp_ping_filter([fast, slow], self.opts, show_progress=False)

        self.assertEqual(kept, [fast])
        self.assertEqual(stats["slow"], 1)
        self.assertEqual(stats["dead"], 1)
        self.assertEqual(stats["alive"], 1)

    def test_report_file_lists_alive_endpoints(self):
        import tempfile
        listener, alive_port = _open_listener()
        self.addCleanup(listener.close)

        with tempfile.TemporaryDirectory() as tmp:
            report = f"{tmp}/alive.txt"
            self.opts["report_file"] = report
            self.mod.tcp_ping_filter(
                [self._vless(alive_port), self._vless(_closed_port())],
                self.opts, show_progress=False,
            )
            with open(report, "r", encoding="utf-8") as f:
                body = f.read()

        self.assertIn(f"127.0.0.1:{alive_port}", body)


class TcpPingConnectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_v2ray_checker()

    def test_refused_port_is_reported_as_refused_not_timeout(self):
        # Refused must be terminal: retrying it would waste the whole timeout budget.
        # Generous timeout on purpose — Windows ConnectEx only refuses after ~2s.
        port = _closed_port()
        latency, reason = asyncio.run(self.mod._tcp_ping_connect("127.0.0.1", port, 8.0))
        self.assertIsNone(latency)
        self.assertIn(reason, ("refused", "unreachable"))

    def test_listening_port_reports_latency(self):
        listener, port = _open_listener()
        self.addCleanup(listener.close)
        latency, reason = asyncio.run(self.mod._tcp_ping_connect("127.0.0.1", port, 2.0))
        self.assertEqual(reason, "ok")
        self.assertIsNotNone(latency)
        self.assertGreaterEqual(latency, 0.0)


if __name__ == "__main__":
    unittest.main()
