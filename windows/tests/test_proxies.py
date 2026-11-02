import importlib.util
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from types import SimpleNamespace

MODULE = Path(__file__).resolve().parents[1] / "proxies.py"
spec = importlib.util.spec_from_file_location("internet_proxy_consumer", MODULE)
proxy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proxy)


class ProxyConsumerTests(unittest.TestCase):
    def test_every_port_and_tls_authority_match_contract(self):
        self.assertEqual(
            [(mode, kind, port) for mode, kind, port, _ in proxy.PORTS],
            [("DIRECT", "HTTP", 4128), ("DIRECT", "SOCKS5", 4080),
             ("DIRECT", "HTTPS", 4443), ("WARP", "HTTP", 3128),
             ("WARP", "SOCKS5", 1080), ("WARP", "HTTPS", 9443)],
        )

    def test_secret_not_in_arguments_and_https_uses_dns_name(self):
        secret = proxy.curl_config("test-user", "test-password")
        with patch.object(proxy.subprocess, "run", return_value=SimpleNamespace(
            returncode=0, stdout="64.176.74.102\n")) as invoked:
            row = proxy.probe(proxy.PORTS[2], "64.176.74.102", "miu.alegria.by", secret)
        args = invoked.call_args.args[0]
        self.assertEqual(row["status"], "PASS")
        self.assertIn("https://miu.alegria.by:4443", args)
        self.assertIn("miu.alegria.by:4443:64.176.74.102", args)
        self.assertNotIn("test-password", " ".join(args))
        self.assertIn("test-password", invoked.call_args.kwargs["input"])
        self.assertTrue(invoked.call_args.kwargs["capture_output"])

    def test_wrong_direct_ip_fails_closed(self):
        with patch.object(proxy.subprocess, "run", return_value=SimpleNamespace(
            returncode=0, stdout="104.28.225.185\n")):
            result = proxy.probe(proxy.PORTS[0], "64.176.74.102", "miu.alegria.by", "dummy")
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["reason_code"], "EGRESS_IP_UNEXPECTED")

    def test_tls_failure_does_not_log_curl_stderr_or_secrets(self):
        with patch.object(proxy.subprocess, "run", return_value=SimpleNamespace(
            returncode=60, stdout="")):
            result = proxy.probe(proxy.PORTS[5], "64.176.74.102", "miu.alegria.by", "dummy")
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["reason_code"], "CURL_EXIT_60")
        self.assertIsNone(result["exit_ip"])


if __name__ == "__main__":
    unittest.main()
