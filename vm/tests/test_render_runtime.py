"""S1 private renderer: acceptance and negative cases without real secrets."""
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import unittest
import uuid

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "render_runtime.py"
spec = importlib.util.spec_from_file_location("internet_runtime_renderer", SCRIPT)
renderer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renderer)


def auth():
    return {
        "schema": "internet-vm-auth-v1",
        "vless_direct_uuid": str(uuid.uuid4()),
        "vless_warp_uuid": str(uuid.uuid4()),
        "hy2_direct_password": "x" * 36,
        "hy2_warp_password": "y" * 36,
        "proxy_user": "internet",
        "proxy_password": "z" * 36,
        "reality_direct_private": "A" * 43,
        "reality_warp_private": "B" * 43,
        "reality_direct_short_id": "aabbccddeeff0011",
        "reality_warp_short_id": "aabbccddeeff0022",
    }


class RuntimeRendererTests(unittest.TestCase):
    def test_render_and_private_files(self):
        payload = auth()
        configs = renderer.prepare(payload, "example.net", "www.cloudflare.com")
        self.assertEqual(set(configs), {"line1.json", "line2.json"})
        self.assertEqual(len(json.loads(configs["line1.json"])["inbounds"]), 4)
        self.assertEqual(len(json.loads(configs["line2.json"])["inbounds"]), 6)
        self.assertNotIn("${", json.dumps(configs))
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "runtime"
            renderer.write_private(target, configs)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)
            for name in configs:
                p = target / name
                self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
                self.assertEqual(p.read_text(), configs[name])

    def test_missing_required_field_rejected(self):
        payload = auth()
        del payload["proxy_password"]
        with self.assertRaisesRegex(ValueError, "AUTH_FIELDS_MISMATCH"):
            renderer.prepare(payload, "example.net", "www.cloudflare.com")

    def test_bad_schema_rejected(self):
        payload = auth()
        payload["schema"] = "unexpected"
        with self.assertRaisesRegex(ValueError, "AUTH_SCHEMA_INVALID"):
            renderer.prepare(payload, "example.net", "www.cloudflare.com")

    def test_invalid_reality_and_weak_password_rejected(self):
        payload = auth()
        payload["reality_direct_private"] = "not a private key"
        with self.assertRaisesRegex(ValueError, "AUTH_REALITY_INVALID"):
            renderer.prepare(payload, "example.net", "www.cloudflare.com")
        payload = auth()
        payload["hy2_warp_password"] = "short"
        with self.assertRaisesRegex(ValueError, "AUTH_PASSWORD_TOO_SHORT"):
            renderer.prepare(payload, "example.net", "www.cloudflare.com")

    def test_unresolved_template_rejected(self):
        with self.assertRaisesRegex(ValueError, "TEMPLATE_REQUIRED_FIELD_MISSING"):
            renderer.render('{"a":"${UNSET}"}', {})

    def test_symlink_destination_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            victim = folder / "target"
            victim.write_text("untouched")
            alias = folder / "runtime"
            alias.symlink_to(folder, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "RUNTIME_PATH_SYMLINK"):
                renderer.write_private(alias, {"line1.json": "bad"})
            self.assertEqual(victim.read_text(), "untouched")


if __name__ == "__main__":
    unittest.main()
