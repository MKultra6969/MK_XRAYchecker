"""Issue #14 generator tests: VLESS REALITY new params + Hysteria2 obfsPassword alias.

Standalone (no external cores). Stubs psutil so v2rayChecker.py imports cleanly
in environments without psutil installed.
"""
import importlib.util
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path


def _install_psutil_stub():
    """Minimal psutil fake so v2rayChecker.py (which `import psutil` at top) loads."""
    if "psutil" in sys.modules and getattr(sys.modules["psutil"], "__mkxray_stub__", False):
        return sys.modules["psutil"]
    if "psutil" in sys.modules:
        return sys.modules["psutil"]

    fake = types.ModuleType("psutil")
    fake.__mkxray_stub__ = True

    class _ProcError(Exception):
        pass

    class NoSuchProcess(_ProcError):
        pass

    class AccessDenied(_ProcError):
        pass

    class ZombieProcess(_ProcError):
        pass

    fake.NoSuchProcess = NoSuchProcess
    fake.AccessDenied = AccessDenied
    fake.ZombieProcess = ZombieProcess

    def pid_exists(pid):
        return False

    class Process:
        def __init__(self, pid=None):
            self.pid = pid

        def cmdline(self):
            return []

        def name(self):
            return ""

        def kill(self):
            pass

        def is_running(self):
            return False

    def process_iter(attrs=None):
        return []

    fake.pid_exists = pid_exists
    fake.Process = Process
    fake.process_iter = process_iter

    sys.modules["psutil"] = fake
    return fake


def _install_rich_stub():
    """Minimal rich fake so v2rayChecker.py loads without the rich dependency.

    Only installed if real `rich` cannot be imported. Covers the names referenced
    at import time (Console(), Text.from_markup via MAIN_LOGGER) plus the other
    imported-but-unused symbols.
    """
    try:
        import rich  # noqa: F401
        return
    except ImportError:
        pass

    rich_pkg = types.ModuleType("rich")
    rich_pkg.__mkxray_stub__ = True

    class _Text:
        @classmethod
        def from_markup(cls, *args, **kwargs):
            obj = cls()
            obj.plain = str(args[0]) if args else ""
            return obj

    class _Console:
        def print(self, *args, **kwargs):
            pass

        def clear(self, *args, **kwargs):
            pass

        def status(self, *args, **kwargs):
            class _Ctx:
                def __enter__(self_inner):
                    return self_inner

                def __exit__(self_inner, *exc):
                    return False

            return _Ctx()

    class _Panel:
        def __init__(self, *args, **kwargs):
            pass

    class _Table:
        def __init__(self, *args, **kwargs):
            pass

        def add_column(self, *args, **kwargs):
            pass

        def add_row(self, *args, **kwargs):
            pass

    class _Progress:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def add_task(self, *args, **kwargs):
            return 0

        def update(self, *args, **kwargs):
            pass

        def advance(self, *args, **kwargs):
            pass

    class _Box:
        ROUNDED = "rounded"
        DOUBLE = "double"

    console_sub = types.ModuleType("rich.console")
    console_sub.Console = _Console
    panel_sub = types.ModuleType("rich.panel")
    panel_sub.Panel = _Panel
    table_sub = types.ModuleType("rich.table")
    table_sub.Table = _Table
    progress_sub = types.ModuleType("rich.progress")
    progress_sub.Progress = _Progress
    progress_sub.SpinnerColumn = type("SpinnerColumn", (), {})
    progress_sub.BarColumn = type("BarColumn", (), {})
    progress_sub.TextColumn = type("TextColumn", (), {})
    progress_sub.TimeElapsedColumn = type("TimeElapsedColumn", (), {})
    progress_sub.TimeRemainingColumn = type("TimeRemainingColumn", (), {})
    prompt_sub = types.ModuleType("rich.prompt")
    prompt_sub.Prompt = type("Prompt", (), {})
    prompt_sub.Confirm = type("Confirm", (), {})
    logging_sub = types.ModuleType("rich.logging")
    logging_sub.RichHandler = type("RichHandler", (), {})
    text_sub = types.ModuleType("rich.text")
    text_sub.Text = _Text
    box_sub = types.ModuleType("rich.box")
    box_sub.ROUNDED = "rounded"
    box_sub.DOUBLE = "double"

    sys.modules["rich"] = rich_pkg
    sys.modules["rich.console"] = console_sub
    sys.modules["rich.panel"] = panel_sub
    sys.modules["rich.table"] = table_sub
    sys.modules["rich.progress"] = progress_sub
    sys.modules["rich.prompt"] = prompt_sub
    sys.modules["rich.logging"] = logging_sub
    sys.modules["rich.text"] = text_sub
    sys.modules["rich.box"] = box_sub
    rich_pkg.console = console_sub
    rich_pkg.text = text_sub
    rich_pkg.box = box_sub


_install_rich_stub()
_install_psutil_stub()


def _load_v2ray_checker():
    repo_root = Path(__file__).resolve().parent
    tmpdir = tempfile.TemporaryDirectory()
    old_cwd = os.getcwd()
    try:
        os.chdir(tmpdir.name)
        spec = importlib.util.spec_from_file_location(
            "_mkxray_v2rayChecker_issue14",
            repo_root / "v2rayChecker.py",
        )
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        return module
    finally:
        os.chdir(old_cwd)
        tmpdir.cleanup()


class Issue14GeneratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_v2ray_checker()

    # --- helpers -----------------------------------------------------------
    @staticmethod
    def _vless_reality_url():
        # REALITY with spx, pqv, pcs, packetEncoding, ed, ech
        return (
            "vless://a3f5b8a1-2c3d-4e5f-8a9b-0c1d2e3f4a5b@example.com:443"
            "?encryption=none&security=reality&sni=example.com&fp=chrome"
            "&pbk=BMv1m1qYk2yV0d2n3x4y5z6a7b8c9d0e1f2g3h4i5j6"
            "&sid=ab12cd34&type=tcp&flow=xtls-rprx-vision"
            "&spx=%2FcustomSpider&pqv=PQV_BLOB&pcs=1&packetEncoding=xudp&ed=2048&ech=BASE64ECHBLOB"
            "#issue14-reality"
        )

    @staticmethod
    def _hysteria2_url():
        return (
            "hysteria2://pass@hy2.example.com:443"
            "?sni=hy2.example.com&insecure=1&obfs=salamander&obfsPassword=secretObfs&alpn=h3,http/1.1"
            "#issue14-hy2"
        )

    # --- tests -------------------------------------------------------------
    def test_vless_reality_parses_issue14_params(self):
        parsed = self.mod.parse_vless(self._vless_reality_url())
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["spiderX"], "/customSpider")
        self.assertEqual(parsed["pqv"], "PQV_BLOB")
        self.assertEqual(parsed["pcs"], "1")
        self.assertEqual(parsed["packet_encoding"], "xudp")
        self.assertEqual(parsed["ed"], "2048")
        self.assertEqual(parsed["ech"], "BASE64ECHBLOB")

    def test_vless_reality_spiderx_defaults_to_slash(self):
        url = (
            "vless://a3f5b8a1-2c3d-4e5f-8a9b-0c1d2e3f4a5b@example.com:443"
            "?encryption=none&security=reality&sni=example.com&fp=chrome"
            "&pbk=BMv1m1qYk2yV0d2n3x4y5z6a7b8c9d0e1f2g3h4i5j6&sid=ab12cd34"
            "&type=tcp#nospx"
        )
        parsed = self.mod.parse_vless(url)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["spiderX"], "/")

    def test_vless_reality_base64url_pqv_ech_preserved(self):
        # base64url-style values with - and _ (REALITY's standard encoding)
        url = (
            "vless://a3f5b8a1-2c3d-4e5f-8a9b-0c1d2e3f4a5b@example.com:443"
            "?encryption=none&security=reality&sni=example.com&fp=chrome"
            "&pbk=BMv1m1qYk2yV0d2n3x4y5z6a7b8c9d0e1f2g3h4i5j6&sid=ab12cd34"
            "&type=tcp&spx=%2Fsp&pqv=A-B_C-D_E&ech=Zm9v-LWJhcg#b64"
        )
        parsed = self.mod.parse_vless(url)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["pqv"], "A-B_C-D_E")
        self.assertEqual(parsed["ech"], "Zm9v-LWJhcg")
        # propagate to Xray REALITY settings
        out = self.mod.get_outbound_structure(url, "out_10000")
        self.assertIsNotNone(out)
        rs = out["streamSettings"]["realitySettings"]
        self.assertEqual(rs["mldsa65Verify"], "A-B_C-D_E")

    def test_xray_outbound_reality_has_spiderx_and_mldsa65verify(self):
        out = self.mod.get_outbound_structure(self._vless_reality_url(), "out_10000")
        self.assertIsNotNone(out)
        rs = out["streamSettings"]["realitySettings"]
        self.assertEqual(rs["spiderX"], "/customSpider")
        self.assertEqual(rs["mldsa65Verify"], "PQV_BLOB")

    def test_xray_outbound_reality_no_mldsa65verify_without_pqv(self):
        url = (
            "vless://a3f5b8a1-2c3d-4e5f-8a9b-0c1d2e3f4a5b@example.com:443"
            "?encryption=none&security=reality&sni=example.com&fp=chrome"
            "&pbk=BMv1m1qYk2yV0d2n3x4y5z6a7b8c9d0e1f2g3h4i5j6&sid=ab12cd34"
            "&type=tcp#nopqv"
        )
        out = self.mod.get_outbound_structure(url, "out_10000")
        self.assertIsNotNone(out)
        rs = out["streamSettings"]["realitySettings"]
        self.assertNotIn("mldsa65Verify", rs)

    def test_xray_outbound_vless_user_encryption_from_param(self):
        url = (
            "vless://a3f5b8a1-2c3d-4e5f-8a9b-0c1d2e3f4a5b@example.com:443"
            "?encryption=custom-enc&security=tls&sni=example.com&type=tcp#enc"
        )
        out = self.mod.get_outbound_structure(url, "out_10000")
        self.assertIsNotNone(out)
        user = out["settings"]["vnext"][0]["users"][0]
        self.assertEqual(user["encryption"], "custom-enc")

    def test_xray_outbound_tls_has_echconfiglist_when_ech_present(self):
        # REALITY path does not set tlsSettings; build a tls URL for ech check.
        url = (
            "vless://a3f5b8a1-2c3d-4e5f-8a9b-0c1d2e3f4a5b@example.com:443"
            "?encryption=none&security=tls&sni=example.com&fp=chrome"
            "&type=tcp&ech=BASE64ECHBLOB#ech"
        )
        out = self.mod.get_outbound_structure(url, "out_10000")
        self.assertIsNotNone(out)
        tls = out["streamSettings"]["tlsSettings"]
        self.assertEqual(tls["echConfigList"], "BASE64ECHBLOB")

    def test_mihomo_reality_has_support_x25519mlkem768_and_packet_encoding(self):
        proxy = self.mod.get_mihomo_proxy_structure(self._vless_reality_url(), "out_10000")
        self.assertIsNotNone(proxy)
        self.assertEqual(proxy["type"], "vless")
        ro = proxy["reality-opts"]
        self.assertTrue(ro["support-x25519mlkem768"])
        self.assertEqual(proxy["packet-encoding"], "xudp")

    def test_mihomo_ech_opts_keeps_config_blob(self):
        proxy = self.mod.get_mihomo_proxy_structure(self._vless_reality_url(), "out_10000")
        self.assertIsNotNone(proxy)
        ech_opts = proxy.get("ech-opts")
        self.assertIsNotNone(ech_opts)
        self.assertTrue(ech_opts["enable"])
        self.assertEqual(ech_opts["config"], "BASE64ECHBLOB")

    def test_mihomo_reality_no_pcs_flag_omits_support_x25519mlkem768(self):
        url = (
            "vless://a3f5b8a1-2c3d-4e5f-8a9b-0c1d2e3f4a5b@example.com:443"
            "?encryption=none&security=reality&sni=example.com&fp=chrome"
            "&pbk=BMv1m1qYk2yV0d2n3x4y5z6a7b8c9d0e1f2g3h4i5j6&sid=ab12cd34"
            "&type=tcp#nopcs"
        )
        proxy = self.mod.get_mihomo_proxy_structure(url, "out_10000")
        self.assertIsNotNone(proxy)
        self.assertNotIn("support-x25519mlkem768", proxy.get("reality-opts", {}))

    def test_mihomo_vless_no_packet_encoding_when_absent(self):
        url = (
            "vless://a3f5b8a1-2c3d-4e5f-8a9b-0c1d2e3f4a5b@example.com:443"
            "?encryption=none&security=reality&sni=example.com&fp=chrome"
            "&pbk=BMv1m1qYk2yV0d2n3x4y5z6a7b8c9d0e1f2g3h4i5j6&sid=ab12cd34"
            "&type=tcp#nope"
        )
        proxy = self.mod.get_mihomo_proxy_structure(url, "out_10000")
        self.assertIsNotNone(proxy)
        self.assertNotIn("packet-encoding", proxy)

    def test_mihomo_ws_early_data_when_ed_present(self):
        url = (
            "vless://a3f5b8a1-2c3d-4e5f-8a9b-0c1d2e3f4a5b@example.com:443"
            "?encryption=none&security=tls&sni=example.com&type=ws&path=%2Fws&ed=2048#ed"
        )
        proxy = self.mod.get_mihomo_proxy_structure(url, "out_10000")
        self.assertIsNotNone(proxy)
        ws = proxy["ws-opts"]
        self.assertEqual(ws["max-early-data"], 2048)

    def test_hysteria2_obfs_password_alias_preserved(self):
        parsed = self.mod.parse_hysteria2(self._hysteria2_url())
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["obfs"], "salamander")
        self.assertEqual(parsed["obfs_password"], "secretObfs")
        self.assertEqual(parsed["alpn"], "h3,http/1.1")

    def test_hysteria2_mihomo_keeps_obfs_password_and_alpn(self):
        proxy = self.mod.get_mihomo_proxy_structure(self._hysteria2_url(), "out_10000")
        self.assertIsNotNone(proxy)
        self.assertEqual(proxy["type"], "hysteria2")
        self.assertEqual(proxy["obfs"], "salamander")
        self.assertEqual(proxy["obfs-password"], "secretObfs")
        self.assertEqual(proxy["alpn"], ["h3", "http/1.1"])

    def test_hysteria2_xray_tls_has_alpn(self):
        out = self.mod.get_outbound_structure(self._hysteria2_url(), "out_10000")
        self.assertIsNotNone(out)
        tls = out["streamSettings"]["tlsSettings"]
        self.assertEqual(tls["alpn"], ["h3", "http/1.1"])

    def test_shadowsocks_still_works_regression(self):
        import base64
        userinfo = base64.b64encode(b"aes-256-gcm:pass").decode("ascii")
        url = f"ss://{userinfo}@ss.example.com:8388#ssreg"
        proxy = self.mod.get_mihomo_proxy_structure(url, "out_10000")
        self.assertIsNotNone(proxy)
        self.assertEqual(proxy["type"], "ss")
        self.assertEqual(proxy["cipher"], "aes-256-gcm")
        out = self.mod.get_outbound_structure(url, "out_10000")
        self.assertIsNotNone(out)
        self.assertEqual(out["protocol"], "shadowsocks")


if __name__ == "__main__":
    unittest.main()
