"""U7 native WireGuard reconnect contract: tests only mocked Linux commands."""
import ast
import contextlib
import io
from pathlib import Path
import types
import unittest


SOURCE = Path(__file__).resolve().parents[2] / "src" / "wsl_tun_guest.py"


def load_functions():
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    funcs = [node for node in tree.body
             if isinstance(node, ast.FunctionDef)
             and node.name in {"wsl_gateway", "prepare"}]
    scope = {}
    exec(compile(ast.Module(body=funcs, type_ignores=[]), str(SOURCE), "exec"), scope)
    return scope


class NativeWireguardReconnectTests(unittest.TestCase):
    def test_nat_gateway_readback_must_be_owned_private_eth0(self):
        scope = load_functions()
        def run(*a, **k):
            return types.SimpleNamespace(stdout="default via 172.26.16.1 dev eth0 proto kernel\n")
        scope["run"] = run
        self.assertEqual(scope["wsl_gateway"](), "172.26.16.1")
        for route in ("default via 8.8.8.8 dev eth0\n",
                      "default via 172.26.16.1 dev wlan0\n",
                      "default via 127.0.0.1 dev eth0\n",
                      "default via 172.26.16.1 dev eth0\ndefault via 172.26.16.2 dev eth0"):
            with self.subTest(route=route):
                scope["run"] = lambda *a, **k: types.SimpleNamespace(stdout=route)
                with self.assertRaises(RuntimeError):
                    scope["wsl_gateway"]()

    def test_guest_prepare_uses_fixed_server_port_and_keepalive(self):
        scope = load_functions()
        commands = []
        def sudo(*args, **kwargs):
            commands.append(args)
            if args[:3] == ("/usr/bin/stat", "-c", "%u:%a"):
                return types.SimpleNamespace(returncode=0, stdout="0:600\n")
            return types.SimpleNamespace(returncode=0, stdout="")
        scope.update({
            "sudo": sudo, "interface_exists": lambda: False,
            "owned_rules": lambda: (False, False, False),
            "wsl_gateway": lambda: "172.26.16.1",
            "assert_owned": lambda: None,
            "IFACE": "internet-wsl", "IP": "10.222.28.2/30",
            "PORT": "43912", "KEY_FILE": "/etc/wireguard/internet-wsl.key",
            "json": __import__("json")
        })
        with contextlib.redirect_stdout(io.StringIO()):
            scope["prepare"]("A" * 43 + "=")
        wg = next(args for args in commands if args[:3] == (
            "/usr/bin/wg", "set", "internet-wsl"))
        self.assertEqual(wg[wg.index("endpoint") + 1], "172.26.16.1:43913")
        self.assertEqual(wg[wg.index("persistent-keepalive") + 1], "2")
        self.assertEqual(wg[wg.index("allowed-ips") + 1], "0.0.0.0/0")


if __name__ == "__main__":
    unittest.main()
