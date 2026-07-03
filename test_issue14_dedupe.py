"""Issue #14 canonical dedupe tests.

Standalone-ish: reuses stub installers + v2rayChecker loader from
test_issue14_generators so we get a clean module import without psutil/rich.
"""
import unittest

from test_issue14_generators import _install_rich_stub, _install_psutil_stub, _load_v2ray_checker

_install_rich_stub()
_install_psutil_stub()


_UUID = "a3f5b8a1-2c3d-4e5f-8a9b-0c1d2e3f4a5b"
# Valid X25519 (base64url -> 32 bytes) REALITY pbk taken from generator tests.
_PBK = "BMv1m1qYk2yV0d2n3x4y5z6a7b8c9d0e1f2g3h4i5j6"
_HOST = "issue14.example.com"
_PORT = 443


def _vless(query, frag=""):
    url = f"vless://{_UUID}@{_HOST}:{_PORT}?{query}"
    if frag or frag == "":
        return url + (("#" + frag) if frag else "")
    return url


class Issue14DedupeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_v2ray_checker()

    # --- helpers -----------------------------------------------------------
    def _dedupe(self, *links):
        text = "\n".join(links)
        result, raw_hits = self.mod.parse_content(text)
        return list(result), raw_hits

    # --- tests -------------------------------------------------------------
    def test_query_order_trash_and_fragment_collapse(self):
        a = "vless://aaa@aaaaaa.aaa:443?pbk=aaa&security=reality"
        b = "vless://aaa@aaaaaa.aaa:443?security=reality&pbk=aaa"
        c = "vless://aaa@aaaaaa.aaa:443?pbk=aaa&security=reality&trash=trash"
        d = "vless://aaa@aaaaaa.aaa:443?pbk=aaa&security=reality#trash"
        result, _ = self._dedupe(a, b, c, d)
        self.assertEqual(len(result), 1, f"expected 1 unique, got {result}")

    def test_different_significant_values_do_not_collapse(self):
        # Same UUID/host/port/security, but different sni must survive.
        u_sni_a = _vless(f"security=reality&pbk={_PBK}&sni=a.example.com&type=tcp")
        u_sni_b = _vless(f"security=reality&pbk={_PBK}&sni=b.example.com&type=tcp")
        result, _ = self._dedupe(u_sni_a, u_sni_b)
        self.assertEqual(len(result), 2, f"different sni must not collapse: {result}")

        # Different transport type must survive.
        u_tcp = _vless(f"security=reality&pbk={_PBK}&sni=a.example.com&type=tcp")
        u_ws = _vless(f"security=reality&pbk={_PBK}&sni=a.example.com&type=ws&path=/x")
        result2, _ = self._dedupe(u_tcp, u_ws)
        self.assertEqual(len(result2), 2, f"different type must not collapse: {result2}")

    def test_fragment_tag_does_not_affect_dedupe(self):
        base = f"vless://{_UUID}@{_HOST}:{_PORT}?security=reality&pbk={_PBK}&sni=a.example.com&type=tcp"
        result, _ = self._dedupe(base, base + "#tagA", base + "#tagB")
        self.assertEqual(len(result), 1, f"fragment/tag must not affect dedupe: {result}")

    def test_canonical_proxy_key_helper(self):
        # Direct helper check: trash params and fragment stripped, query order stable.
        a = "vless://aaa@aaaaaa.aaa:443?pbk=aaa&security=reality"
        b = "vless://aaa@aaaaaa.aaa:443?security=reality&pbk=aaa&trash=x#frag"
        self.assertEqual(self.mod.canonical_proxy_key(a), self.mod.canonical_proxy_key(b))
        # Different protocol/unsupported falls back to fragment-stripped string.
        self.assertTrue(self.mod.canonical_proxy_key("weird://x@y:1?p=1#t").startswith("fallback:"))
        self.assertEqual(
            self.mod.canonical_proxy_key("weird://x@y:1#t"),
            self.mod.canonical_proxy_key("weird://x@y:1"),
        )


if __name__ == "__main__":
    unittest.main()