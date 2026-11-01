#!/usr/bin/env python3
"""Native sing-box config validation with EPHEMERAL dummy credentials.

No production secrets, no listening ports, no external service access.
Docker executes the exact digest-pinned image from vm/images.env.example.
"""
import os
import re
import sys
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.render_runtime import prepare
ENV = ROOT / "images.env.example"


def run(*args, **kw):
    return subprocess.run(args, check=True, text=True, capture_output=True, **kw)


def image():
    for line in ENV.read_text().splitlines():
        if line.startswith("INTERNET_SING_BOX_IMAGE="):
            image_ref = line.split("=", 1)[1]
            if not re.search(r"@sha256:[a-f0-9]{64}$", image_ref):
                raise ValueError("sing-box image not digest-pinned")
            return image_ref
    raise ValueError("sing-box image missing")


def fixtures():
    # Validate exactly the Reality keys emitted by the production generator.
    from tools.generate_auth import generate
    return generate()


def check():
    img = image()
    with tempfile.TemporaryDirectory(prefix="internet-s1-native-") as tmp:
        tmp = Path(tmp)
        domain = "miu.alegria.by"
        # Mock the exact CertMagic file layout that Line1 ACME shares with Line2.
        cert_dir = tmp / "certificates" / "acme-v02.api.letsencrypt.org-directory" / domain
        cert_dir.mkdir(parents=True)
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-keyout", str(cert_dir / (domain + ".key")),
            "-out", str(cert_dir / (domain + ".crt")),
            "-subj", "/CN=" + domain)
        configs = prepare(fixtures(), "miu.alegria.by", "www.cloudflare.com")
        for name in ("line1", "line2"):
            value = configs[name + ".json"]
            config_path = tmp / (name + ".json")
            config_path.write_text(value)
            os.chmod(config_path, 0o600)
            check_result = subprocess.run(
                ["docker", "run", "--rm", "--network", "none",
                 "-v", str(tmp) + ":/check:ro",
                 "-v", str(tmp) + ":/var/lib/sing-box:ro",
                 img, "check", "-c", "/check/" + name + ".json"],
                capture_output=True, text=True)
            if check_result.returncode:
                print(name + " NATIVE_CHECK_FAIL")
                print(check_result.stderr[-1600:])
                return 1
            print(name + " NATIVE_CHECK_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(check())
