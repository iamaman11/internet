"""Native Windows proxy checks must work independently of the Ubuntu WG route.

Tests use fake process results: no network, no Vault credentials and no secrets
are emitted to argv or logs.
"""
import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch


MODULE = Path(__file__).resolve().parents[1] / "proxies.py"
spec = importlib.util.spec_from_file_location("internet_proxies", MODULE)
proxies = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proxies)


class WindowsProxyProbeTests(unittest.TestCase):
    def test_native_windows_curl_and_credentials_only_on_stdin(self):
        auth = proxies.curl_config("example-user", 'complex\\password"withquote')
        fake = subprocess.CompletedProcess([], 0, "64.176.74.102\n", "")
        with patch.object(proxies.subprocess, "run", return_value=fake) as run:
            result = proxies.probe(
                ("DIRECT", "HTTP", 4128, "http"),
                "64.176.74.102", "miu.alegria.by", auth)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["exit_ip"], "64.176.74.102")
        args = run.call_args.args[0]
        self.assertEqual(args[0], "/mnt/c/Windows/System32/curl.exe")
        self.assertEqual(args[args.index("-K") + 1], "-")
        self.assertEqual(run.call_args.kwargs["input"], auth)
        self.assertNotIn("example-user", " ".join(args))
        self.assertNotIn("complex", " ".join(args))
        self.assertNotIn("complex", str(result))
        self.assertTrue(run.call_args.kwargs["capture_output"])

    def test_socks_and_https_keep_original_proxy_transport(self):
        for item, scheme in [
            (("DIRECT", "SOCKS5", 4080, "socks5h"), "socks5h"),
            (("DIRECT", "HTTPS", 4443, "https"), "https"),
        ]:
            with self.subTest(item=item):
                fake = subprocess.CompletedProcess([], 0, "64.176.74.102", "")
                with patch.object(proxies.subprocess, "run", return_value=fake) as run:
                    result = proxies.probe(item, "64.176.74.102", "miu.alegria.by", "proxy-user = \"test\"\n")
                args = run.call_args.args[0]
                self.assertTrue(args[0].endswith("/Windows/System32/curl.exe"))
                self.assertIn("--proxy", args)
                self.assertTrue(args[args.index("--proxy") + 1].startswith(scheme + "://"))
                self.assertEqual(result["status"], "PASS")
                if scheme == "https":
                    self.assertIn("--resolve", args)

    def test_timeout_and_failure_never_disclose_private_auth(self):
        secret = 'proxy-user = "a:sensitive-value"\n'
        for response in [subprocess.TimeoutExpired("curl", 5),
                         subprocess.CompletedProcess([], 28, "", "secret unrelated error")]:
            with self.subTest(case=type(response).__name__):
                with patch.object(proxies.subprocess, "run",
                                  side_effect=response if isinstance(response, Exception) else None,
                                  return_value=response if not isinstance(response, Exception) else None):
                    got = proxies.probe(("WARP", "HTTP", 3128, "http"),
                                        "64.176.74.102", "miu.alegria.by", secret)
                self.assertNotEqual(got["status"], "PASS")
                self.assertNotIn("sensitive", str(got))
                self.assertIsNone(got["exit_ip"])


if __name__ == "__main__":
    unittest.main()
