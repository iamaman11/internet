"""Pure tests for S1 ephemeral Line1 probes; no Docker or production secrets."""
import base64
import sys
from pathlib import Path
import unittest

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe_line1_local import SPECS, ProbeError, config_for, outbound_for, public_from_private, read_inbounds, REMOTE_SERVER


def private_test_key():
    key = X25519PrivateKey.generate()
    raw = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def vless_inbound():
    return {
        "type": "vless", "listen_port": 443,
        "users": [{"uuid": "c14d5df0-6bd4-4efb-8e38-c31a1b2a23b4",
                   "flow": "xtls-rprx-vision"}],
        "tls": {"reality": {"private_key": private_test_key(),
                           "short_id": ["aabbccdd"]}},
    }


def hy2_inbound():
    return {
        "type": "hysteria2", "listen_port": 8443,
        "users": [{"password": "test-password-not-secret"}],
    }


class TestLine1Probe(unittest.TestCase):
    def test_four_protocol_ports_and_egress_paths(self):
        self.assertEqual([(kind, port, route) for _, kind, port, route in SPECS], [
            ("vless", 443, "direct"),
            ("hysteria2", 8443, "direct"),
            ("vless", 5443, "warp"),
            ("hysteria2", 9444, "warp"),
        ])

    def test_derived_reality_public_key_matches_private(self):
        private = private_test_key()
        pub = public_from_private(private)
        self.assertEqual(len(base64.urlsafe_b64decode(pub + "=" * (-len(pub) % 4))), 32)

    def test_reality_client_tls_flow_and_ip(self):
        cfg = config_for(vless_inbound(), 18452)
        outbound = cfg["outbounds"][0]
        self.assertEqual(outbound["flow"], "xtls-rprx-vision")
        self.assertEqual(outbound["server"], "127.0.0.1")
        self.assertEqual(outbound["server_port"], 443)
        self.assertEqual(outbound["tls"]["server_name"], "www.cloudflare.com")
        self.assertEqual(outbound["tls"]["utls"], {"enabled": True, "fingerprint": "chrome"})
        self.assertTrue(outbound["tls"]["reality"]["public_key"])
        self.assertEqual(cfg["inbounds"][0]["listen"], "127.0.0.1")

    def test_invalid_reality_uuid_is_not_valid_uuid(self):
        valid = outbound_for(vless_inbound())
        invalid = outbound_for(vless_inbound(), invalid=True)
        self.assertNotEqual(valid["uuid"], invalid["uuid"])
        self.assertEqual(invalid["uuid"], "00000000-0000-4000-8000-000000000000")

    def test_hy2_client_tls_hostname_and_password(self):
        valid = outbound_for(hy2_inbound())
        invalid = outbound_for(hy2_inbound(), invalid=True)
        self.assertEqual(valid["type"], "hysteria2")
        self.assertEqual(valid["tls"]["server_name"], "miu.alegria.by")
        self.assertEqual(valid["tls"]["alpn"], ["h3"])
        self.assertEqual(valid["password"], "test-password-not-secret")
        self.assertNotEqual(invalid["password"], valid["password"])

    def test_invalid_reality_key_rejected(self):
        inbound = vless_inbound()
        inbound["tls"]["reality"]["private_key"] = "too-short"
        with self.assertRaisesRegex(ProbeError, "REALITY_PRIVATE_KEY_INVALID"):
            outbound_for(inbound)

    def test_external_mode_uses_target_vm_without_changing_local_default(self):
        local = config_for(vless_inbound(), 18452)
        external = config_for(vless_inbound(), 18452, server=REMOTE_SERVER)
        self.assertEqual(local["outbounds"][0]["server"], "127.0.0.1")
        self.assertEqual(external["outbounds"][0]["server"], "64.176.74.102")

    def test_external_mode_requires_existing_vault_binding(self):
        import os
        from unittest.mock import patch
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ProbeError, "VAULT_BINDING_MISSING"):
                read_inbounds(from_vault=True)

    def test_unknown_protocol_rejected(self):
        inbound = hy2_inbound()
        inbound["type"] = "http"
        with self.assertRaisesRegex(ProbeError, "INBOUND_KIND_UNSUPPORTED"):
            outbound_for(inbound)


if __name__ == "__main__":
    unittest.main()
