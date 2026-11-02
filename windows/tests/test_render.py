"""Safe fixture tests of the real Vault auth→Windows config renderer."""
import unittest
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "windows"))
sys.path.insert(0, str(ROOT / "vm" / "tools"))
from configure_from_vault import build, ROUTES
from generate_auth import generate


class RenderTest(unittest.TestCase):
    def setUp(self):
        self.auth = generate()

    def test_six_x_two_and_no_direct_warp_fallback(self):
        config = build(self.auth, "64.176.74.102")
        tags = {o["tag"]: o for o in config["outbounds"]}
        self.assertEqual(len(tags), 8)
        for name in ("desktop-selector", "wsl-selector"):
            self.assertEqual(tags[name]["outbounds"], ROUTES)
        self.assertEqual(tags["warp-auto"]["outbounds"],
                         ["warp-hysteria2", "warp-vless"])
        self.assertEqual(tags["direct-auto"]["outbounds"],
                         ["direct-hysteria2", "direct-vless"])
        self.assertNotIn("type", config.get("tun", {}))
        self.assertEqual(config["inbounds"][1]["listen"], "127.0.0.1")
        self.assertEqual(config["inbounds"][1]["users"][0]["username"], self.auth["proxy_user"])

    def test_different_modes_really_use_different_credentials(self):
        c = build(self.auth, "64.176.74.102")
        x = {o["tag"]: o for o in c["outbounds"]}
        self.assertNotEqual(x["direct-vless"]["uuid"], x["warp-vless"]["uuid"])
        self.assertNotEqual(x["direct-hysteria2"]["password"],
                            x["warp-hysteria2"]["password"])
        self.assertNotIn("private_key", x["direct-vless"]["tls"]["reality"])

    def test_required_public_endpoint_and_no_historical_default(self):
        for bad in ("", "127.0.0.1", "192.168.1.1", "203.0.113.7", "not-an-ip"):
            with self.assertRaises(ValueError, msg=bad):
                build(self.auth, bad)
        c = build(self.auth, "8.8.8.8")
        self.assertEqual({o["server"] for o in c["outbounds"] if "server" in o},
                         {"8.8.8.8"})

    def test_invalid_bundle_is_rejected(self):
        self.auth["schema"] = "legacy"
        with self.assertRaises(ValueError):
            build(self.auth, "64.176.74.102")

if __name__ == "__main__":
    unittest.main()
