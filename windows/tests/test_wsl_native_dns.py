"""Non-invasive contract tests for the native WSL DNS executor.

Never import/execute the guest module: its entrypoint controls real routes.
"""
import ast
import configparser
import os
from pathlib import Path
import tempfile
import types
import unittest


SOURCE = Path(__file__).resolve().parents[2] / "src" / "wsl_tun_guest.py"


def guest_ast():
    return ast.parse(SOURCE.read_text(encoding="utf-8"))


def guest_literal(name):
    for node in guest_ast().body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == name for t in node.targets
        ):
            return ast.literal_eval(node.value)
    raise AssertionError(f"missing constant: {name}")


class WslNativeDnsTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory(prefix="internet-wsl-dns-")
        self.addCleanup(self.dir.cleanup)
        root = Path(self.dir.name)
        self.conf = root / "etc" / "wsl.conf"
        self.policy = root / "etc" / "systemd" / "resolved.conf.d" / "internet-wsl.conf"
        self.link = root / "etc" / "resolv.conf"
        self.stub = root / "run" / "systemd" / "resolve" / "stub-resolv.conf"
        for p in (self.conf, self.policy, self.link, self.stub):
            p.parent.mkdir(parents=True, exist_ok=True)
        self.conf.write_text("[boot]\nsystemd=true\n[network]\ngenerateResolvConf=false\n")
        self.policy.write_text(guest_literal("RESOLVED_POLICY"))
        self.stub.write_text("nameserver 127.0.0.53\n")
        self.link.symlink_to(self.stub)

        lookup = {"/etc/wsl.conf": self.conf, "/etc/resolv.conf": self.link,
                  guest_literal("RESOLVED_CONF"): self.policy}
        fake_pathlib = types.SimpleNamespace(Path=lambda key: Path(lookup.get(str(key), key)))
        functions = [n for n in guest_ast().body
                     if isinstance(n, ast.FunctionDef)
                     and n.name in {"dns_boot_configured", "dns_ready"}]
        self.ctx = {"configparser": configparser, "os": os,
                    "pathlib": fake_pathlib, "STUB_RESOLV": str(self.stub),
                    "RESOLVED_CONF": guest_literal("RESOLVED_CONF"),
                    "RESOLVED_POLICY": guest_literal("RESOLVED_POLICY")}
        exec(compile(ast.Module(body=functions, type_ignores=[]), str(SOURCE), "exec"),
             self.ctx)

    def ready(self):
        return self.ctx["dns_ready"]()

    def test_systemd_resolved_owned_native_boot_is_ready(self):
        self.assertEqual(guest_literal("RESOLVED_POLICY"),
                         "[Resolve]\nDNS=1.1.1.1 8.8.8.8\n")
        self.assertTrue(self.ready())

    def test_generated_wsl_resolver_is_not_native(self):
        self.link.unlink()
        self.link.symlink_to(self.dir.name + "/mnt/wsl/resolv.conf")
        self.assertFalse(self.ready())

    def test_foreign_resolver_policy_is_rejected(self):
        self.policy.write_text("[Resolve]\nDNS=8.8.4.4\n")
        self.assertFalse(self.ready())

    def test_wsl_dns_generation_enabled_is_rejected(self):
        self.conf.write_text("[network]\ngenerateResolvConf=true\n")
        self.assertFalse(self.ready())

    def test_missing_network_ownership_is_rejected(self):
        self.conf.write_text("[boot]\nsystemd=true\n")
        self.assertFalse(self.ready())

    def test_embedded_root_helper_is_syntactically_valid(self):
        setup = next(n for n in guest_ast().body
                     if isinstance(n, ast.FunctionDef) and n.name == "dns_setup")
        assignment = next(n for n in ast.walk(setup)
                          if isinstance(n, ast.Assign)
                          and any(isinstance(t, ast.Name) and t.id == "root_code"
                                  for t in n.targets))
        helper = ast.literal_eval(assignment.value)
        parsed = ast.parse(helper)
        expected = "[Resolve]\nDNS=1.1.1.1 8.8.8.8\n".encode()
        policy = next(n for n in parsed.body
                      if isinstance(n, ast.Assign)
                      and any(isinstance(t, ast.Name) and t.id == "new_policy"
                              for t in n.targets))
        self.assertEqual(ast.literal_eval(policy.value), expected)


if __name__ == "__main__":
    unittest.main()
