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
        config = build(self.auth)
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

    def test_different_modes_really_use_different_credentials(self):
        c = build(self.auth)
        x = {o["tag"]: o for o in c["outbounds"]}
        self.assertNotEqual(x["direct-vless"]["uuid"], x["warp-vless"]["uuid"])
        self.assertNotEqual(x["direct-hysteria2"]["password"],
                            x["warp-hysteria2"]["password"])
        self.assertNotIn("private_key", x["direct-vless"]["tls"]["reality"])

    def test_invalid_bundle_is_rejected(self):
        self.auth["schema"] = "legacy"
        with self.assertRaises(ValueError):
            build(self.auth)

if __name__ == "__main__":
    unittest.main()
