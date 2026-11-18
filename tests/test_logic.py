"""Unit tests for the pure logic of vpn_indicator (no GTK, no network).

Run: python3 -m unittest discover -s tests
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import vpn_indicator as vi  # noqa: E402


def make_iface(root, name, type_, up):
    d = root / name
    d.mkdir()
    (d / "type").write_text(f"{type_}\n")
    (d / "flags").write_text("0x1091\n" if up else "0x1090\n")


class FlagTest(unittest.TestCase):
    def test_codes(self):
        self.assertEqual(vi.flag("NL"), "🇳🇱")
        self.assertEqual(vi.flag("ru"), "🇷🇺")
        self.assertEqual(vi.flag("??"), "🏳")
        self.assertEqual(vi.flag(None), "🏳")


class FindIfaceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_autodetects_up_tun(self):
        make_iface(self.root, "eth0", 1, True)
        make_iface(self.root, "FlClashX", 65534, True)
        self.assertEqual(vi.find_vpn_iface(self.root), "FlClashX")

    def test_down_tun_is_off(self):
        make_iface(self.root, "eth0", 1, True)
        make_iface(self.root, "tun0", 65534, False)
        self.assertIsNone(vi.find_vpn_iface(self.root))

    def test_ignore_globs(self):
        make_iface(self.root, "tailscale0", 65534, True)
        self.assertIsNone(vi.find_vpn_iface(self.root, ignore=["tailscale*"]))

    def test_explicit_names_skip_type_check(self):
        make_iface(self.root, "myvpn", 1, True)
        make_iface(self.root, "tun0", 65534, True)
        self.assertEqual(vi.find_vpn_iface(self.root, names=["myvpn"]), "myvpn")
        self.assertIsNone(vi.find_vpn_iface(self.root, names=["absent"]))


class ClassifyTest(unittest.TestCase):
    def test_first_observation_recorded_silently(self):
        self.assertEqual(vi.classify(None, True, "1.1.1.1"), (True, None))

    def test_unchanged(self):
        self.assertEqual(vi.classify({"ip": "1.1.1.1", "vpn": True}, True, "1.1.1.1"), (False, None))

    def test_ip_change_inside_vpn_is_highlighted(self):
        self.assertEqual(vi.classify({"ip": "1.1.1.1", "vpn": True}, True, "2.2.2.2"), (True, "ip_changed"))

    def test_toggle(self):
        self.assertEqual(vi.classify({"ip": "1.1.1.1", "vpn": False}, True, "2.2.2.2"), (True, "vpn_on"))
        self.assertEqual(vi.classify({"ip": "2.2.2.2", "vpn": True}, False, "1.1.1.1"), (True, "vpn_off"))

    def test_ip_change_without_vpn_recorded_not_highlighted(self):
        self.assertEqual(vi.classify({"ip": "1.1.1.1", "vpn": False}, False, "3.3.3.3"), (True, None))


class ProxyTest(unittest.TestCase):
    def test_manual_local_http(self):
        url = "http://127.0.0.1:7890"
        self.assertEqual(vi.proxy_from_settings("manual", "127.0.0.1", 7890, "", 0),
                         ({"http": url, "https": url}, True))

    def test_socks_only_used_as_mixed_port(self):
        self.assertEqual(vi.proxy_from_settings("manual", "", 0, "localhost", 7891)[0]["https"],
                         "http://localhost:7891")

    def test_remote_proxy_is_not_vpn(self):
        self.assertFalse(vi.proxy_from_settings("manual", "proxy.corp", 3128, "", 0)[1])

    def test_disabled(self):
        self.assertEqual(vi.proxy_from_settings("none", "127.0.0.1", 7890, "127.0.0.1", 7890), (None, False))
        self.assertEqual(vi.proxy_from_settings("auto", "", 0, "", 0), (None, False))


class FormatTest(unittest.TestCase):
    def test_label(self):
        t = vi.TEXTS["en"]
        self.assertEqual(vi.format_label(True, "1.2.3.4", "NL", t), "VPN 🇳🇱 NL · 1.2.3.4")
        self.assertEqual(vi.format_label(False, "1.2.3.4", "RU", t, highlight=True), "⚠ off 🇷🇺 RU · 1.2.3.4")
        self.assertEqual(vi.format_label(False, None, None, t), "— · no network")

    def test_lang(self):
        self.assertEqual(vi.pick_lang({"LANG": "ru_RU.UTF-8"}), "ru")
        self.assertEqual(vi.pick_lang({"LANG": "de_DE.UTF-8"}), "en")
        self.assertEqual(vi.pick_lang({"LANG": "ru_RU.UTF-8", "VPN_LANG": "en"}), "en")


class HistoryTest(unittest.TestCase):
    def test_roundtrip_skips_broken_lines(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "sub" / "h.jsonl"
            vi.append_history({"ip": "1.1.1.1"}, p)
            with p.open("a") as f:
                f.write("garbage\n")
            vi.append_history({"ip": "2.2.2.2"}, p)
            self.assertEqual([e["ip"] for e in vi.load_history(p)], ["1.1.1.1", "2.2.2.2"])


if __name__ == "__main__":
    unittest.main()
