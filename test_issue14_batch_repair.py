"""Issue #14 batch-repair helper tests.

Tracked counterpart to the ignored test_v2ray_checker_ss_mihomo.py batch
checks: covers extract_bad_outbound_tag + drop_proxy_by_outbound_tag without
touching .gitignore or v2rayChecker.py. Reuses the stub/loader from
test_issue14_generators for a clean module import (no psutil/rich needed).
"""
import unittest

from test_issue14_generators import _install_rich_stub, _install_psutil_stub, _load_v2ray_checker

_install_rich_stub()
_install_psutil_stub()


class Issue14BatchRepairTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_v2ray_checker()

    # --- extract_bad_outbound_tag -----------------------------------------
    def test_extract_bad_outbound_tag_match(self):
        log = '2024/01/01 12:00:00 error: failed to build outbound config with tag out_10000'
        self.assertEqual(self.mod.extract_bad_outbound_tag(log), "out_10000")

    def test_extract_bad_outbound_tag_quote_and_colon_variant(self):
        log = 'inf: failed to build outbound config with tag: "out_12345" more text'
        self.assertEqual(self.mod.extract_bad_outbound_tag(log), "out_12345")

    def test_extract_bad_outbound_tag_irrelevant_empty_none_returns_none(self):
        self.assertIsNone(self.mod.extract_bad_outbound_tag("some unrelated stderr noise"))
        self.assertIsNone(self.mod.extract_bad_outbound_tag(""))
        self.assertIsNone(self.mod.extract_bad_outbound_tag(None))

    # --- drop_proxy_by_outbound_tag ---------------------------------------
    def test_drop_proxy_removes_matching_url_no_mutation(self):
        urls = ["ss://a@host:1", "ss://b@host:2", "ss://c@host:3"]
        valid_mapping = [(urls[0], 10000), (urls[1], 10001), (urls[2], 10002)]
        original = list(urls)
        new_list, dropped = self.mod.drop_proxy_by_outbound_tag(urls, valid_mapping, "out_10001")
        self.assertEqual(dropped, "ss://b@host:2")
        self.assertEqual(new_list, [urls[0], urls[2]])
        # исходный список не мутирован и возвращён список — отдельный объект
        self.assertEqual(urls, original)
        self.assertIsNot(new_list, urls)

    def test_drop_proxy_unknown_tag_no_change_dropped_none(self):
        urls = ["ss://a@host:1"]
        valid_mapping = [(urls[0], 10000)]
        new_list, dropped = self.mod.drop_proxy_by_outbound_tag(urls, valid_mapping, "out_99999")
        self.assertIsNone(dropped)
        self.assertEqual(new_list, urls)
        self.assertIsNot(new_list, urls)

    def test_drop_proxy_bad_tag_no_change_dropped_none(self):
        urls = ["ss://a@host:1"]
        valid_mapping = [(urls[0], 10000)]
        new_list, dropped = self.mod.drop_proxy_by_outbound_tag(urls, valid_mapping, "not_a_tag")
        self.assertIsNone(dropped)
        self.assertEqual(new_list, urls)
        self.assertIsNot(new_list, urls)


if __name__ == "__main__":
    unittest.main()