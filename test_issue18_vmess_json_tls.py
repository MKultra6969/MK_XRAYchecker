"""Issue #18: vmess JSON "tls" as a bool or other non-string value must not crash."""
import base64
import json
import os
import unittest

from test_issue14_generators import _load_v2ray_checker

_MISSING = object()

ISSUE_18_JSON = (
    '{"add":"93ucrn4i0pffuabk.v.3dns.vip","aid":0,"host":"93ucrn4i0pffuabk.v.3dns.vip",'
    '"id":"f23bb427-c1f9-4373-876c-2f43e9f790f3","net":"ws","path":"/ws-vmess","port":443,'
    '"ps":"By EbraSha","scy":"auto","sni":"","tls":true,"type":null,"v":2}'
)


def _vmess_json(**overrides):
    data = {
        "v": "2", "ps": "issue18", "add": "example.com", "port": "443",
        "id": "a3f5b8a1-2c3d-4e5f-8a9b-0c1d2e3f4a5b", "aid": "0", "scy": "auto",
        "net": "ws", "path": "/ws", "host": "example.com", "tls": "tls",
        "sni": "example.com", "fp": "chrome",
    }
    for key, value in overrides.items():
        if value is _MISSING:
            data.pop(key, None)
        else:
            data[key] = value
    return "vmess://" + base64.b64encode(json.dumps(data).encode()).decode()


class Issue18VmessJsonTlsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        old = os.environ.get("MKXRAY_SKIP_PENDING_APPLY")
        os.environ["MKXRAY_SKIP_PENDING_APPLY"] = "1"
        try:
            cls.mod = _load_v2ray_checker()
        finally:
            if old is None:
                os.environ.pop("MKXRAY_SKIP_PENDING_APPLY", None)
            else:
                os.environ["MKXRAY_SKIP_PENDING_APPLY"] = old

    def test_tls_string_tls(self):
        parsed = self.mod.parse_vmess(_vmess_json(tls="tls"))
        self.assertEqual(parsed["security"], "tls")
        self.assertEqual(parsed["address"], "example.com")
        self.assertIsInstance(parsed["port"], int)
        self.assertEqual(parsed["port"], 443)
        self.assertEqual(parsed["type"], "ws")
        self.assertEqual(parsed["path"], "/ws")
        self.assertEqual(parsed["sni"], "example.com")
        self.assertEqual(parsed["tag"], "issue18")

    def test_falsy_or_unknown_tls_maps_to_none(self):
        for value in ("", _MISSING, None, False, 0, "none", "auto", "false", "0", "aes-128-gcm"):
            with self.subTest(tls=value):
                self.assertEqual(self.mod.parse_vmess(_vmess_json(tls=value))["security"], "none")

    def test_truthy_tls_maps_to_tls(self):
        for value in (True, 1, "true", "TRUE", "1", "TLS", "xtls"):
            with self.subTest(tls=value):
                self.assertEqual(self.mod.parse_vmess(_vmess_json(tls=value))["security"], "tls")

    def test_issue18_example_link(self):
        link = "vmess://" + base64.b64encode(ISSUE_18_JSON.encode()).decode()
        host = "93ucrn4i0pffuabk.v.3dns.vip"
        self.assertEqual(self.mod.parse_vmess(link)["security"], "tls")
        self.assertEqual(self.mod.protocol_capability(link), "xray")
        out = self.mod.get_outbound_structure(link, "proxy")
        self.assertIsNotNone(out)
        self.assertEqual(out["streamSettings"]["security"], "tls")
        self.assertEqual(out["streamSettings"]["tlsSettings"]["serverName"], host)
        proxy = self.mod.get_mihomo_proxy_structure(link, "p")
        self.assertIsInstance(proxy, dict)
        self.assertIs(proxy["tls"], True)
        self.assertEqual(proxy["servername"], host)

    def test_tls_control_reaches_both_builders(self):
        link = _vmess_json(tls="tls")
        out = self.mod.get_outbound_structure(link, "out_1")
        stream = out["streamSettings"]
        self.assertEqual(out["protocol"], "vmess")
        self.assertEqual(stream["network"], "ws")
        self.assertEqual(stream["security"], "tls")
        self.assertEqual(stream["tlsSettings"]["serverName"], "example.com")
        self.assertEqual(stream["tlsSettings"]["fingerprint"], "chrome")
        self.assertEqual(stream["wsSettings"]["path"], "/ws")
        proxy = self.mod.get_mihomo_proxy_structure(link, "out_1")
        self.assertEqual(proxy["type"], "vmess")
        self.assertIs(proxy["tls"], True)
        self.assertEqual(proxy["servername"], "example.com")
        self.assertEqual(proxy["client-fingerprint"], "chrome")
        self.assertEqual(proxy["network"], "ws")
        self.assertEqual(proxy["ws-opts"]["path"], "/ws")

    def test_null_ps_gives_empty_tag(self):
        link = _vmess_json(ps=None)
        self.assertEqual(self.mod.parse_vmess(link)["tag"], "")
        self.assertEqual(self.mod.get_proxy_tag(link), "proxy")

    def test_alpn_list_is_joined(self):
        link = _vmess_json(alpn=["h2", "http/1.1"])
        self.assertEqual(self.mod.parse_vmess(link)["alpn"], "h2,http/1.1")
        self.assertIsNotNone(self.mod.get_outbound_structure(link, "out_1"))
        self.assertIsNotNone(self.mod.get_mihomo_proxy_structure(link, "out_1"))

    def test_null_text_fields_become_empty(self):
        link = _vmess_json(host=None, path=None, sni=None, fp=None)
        parsed = self.mod.parse_vmess(link)
        for key in ("host", "path", "sni", "fp"):
            with self.subTest(field=key):
                self.assertEqual(parsed[key], "")
        self.assertIsNotNone(self.mod.get_outbound_structure(link, "out_1"))
        self.assertIsNotNone(self.mod.get_mihomo_proxy_structure(link, "out_1"))

    def test_falsy_json_values_keep_fallbacks(self):
        # False must not become "False", so the host and "chrome" fallbacks still apply
        with self.subTest(case="sni False -> host"):
            link = _vmess_json(sni=False, host="h.example.com")
            out = self.mod.get_outbound_structure(link, "out_1")
            self.assertEqual(out["streamSettings"]["tlsSettings"]["serverName"], "h.example.com")
            proxy = self.mod.get_mihomo_proxy_structure(link, "out_1")
            self.assertEqual(proxy["servername"], "h.example.com")

        with self.subTest(case="fp False -> chrome"):
            link = _vmess_json(fp=False)
            out = self.mod.get_outbound_structure(link, "out_1")
            self.assertEqual(out["streamSettings"]["tlsSettings"]["fingerprint"], "chrome")

        # 0 must not become "0"
        with self.subTest(case="path 0"):
            self.assertEqual(self.mod.parse_vmess(_vmess_json(path=0))["path"], "")

        # a one-item list unwraps to its item, not a Python repr
        with self.subTest(case="host list"):
            self.assertEqual(self.mod.parse_vmess(_vmess_json(host=["a.example.com"]))["host"], "a.example.com")

    def test_protocol_capability_catches_builder_errors(self):
        original_xray = self.mod.get_outbound_structure
        original_mihomo = self.mod.get_mihomo_proxy_structure
        self.addCleanup(setattr, self.mod, "get_outbound_structure", original_xray)
        self.addCleanup(setattr, self.mod, "get_mihomo_proxy_structure", original_mihomo)

        def broken_mihomo(proxy_url, name):
            raise RuntimeError("builder failed")

        self.mod.get_outbound_structure = lambda proxy_url, tag: None
        self.mod.get_mihomo_proxy_structure = broken_mihomo
        self.assertEqual(self.mod.protocol_capability(_vmess_json()), "unsupported")


if __name__ == "__main__":
    unittest.main()
