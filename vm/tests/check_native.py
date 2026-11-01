#!/usr/bin/env python3
"""Native sing-box config validation with EPHEMERAL dummy credentials.

No production secrets, no listening ports, no external service access.
Docker executes the exact digest-pinned image from vm/images.env.example.
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT))
from tools.render_runtime import prepare
ENV = ROOT / "images.env.example"
VARS = re.compile(r"\$\{([A-Z][A-Z0-9_]*)\}")


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


def fixtures(img):
    from tools.generate_auth import generate
    reality = run("docker", "run", "--rm", "--network", "none",
                  img, "generate", "reality-keypair").stdout
    values = {}
    for line in reality.splitlines():
        if ":" in line:
            key, val = line.split(":", 1)
            values[key.strip().lower()] = val.strip()
    private = values.get("privatekey") or values.get("private key")
    if not private:
        raise ValueError("unable to create ephemeral Reality test key")
    payload = generate()
    payload["reality_direct_private"] = private
    payload["reality_warp_private"] = private
    return payload


def check():
    img = image()
    with tempfile.TemporaryDirectory(prefix="internet-s1-native-") as tmp:
        tmp = Path(tmp)
        cert_dir = tmp / "tls"
        cert_dir.mkdir()
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-keyout", str(cert_dir / "tunnel.key"), "-out", str(cert_dir / "tunnel.crt"),
            "-subj", "/CN=miu.alegria.by")
        (cert_dir / "proxy.crt").write_bytes((cert_dir / "tunnel.crt").read_bytes())
        (cert_dir / "proxy.key").write_bytes((cert_dir / "tunnel.key").read_bytes())
        configs = prepare(fixtures(img), "miu.alegria.by", "www.cloudflare.com")
        for name in ("line1", "line2"):
            value = configs[name + ".json"]
            config_path = tmp / (name + ".json")
            config_path.write_text(value)
            os.chmod(config_path, 0o600)
            check_result = subprocess.run(
                ["docker", "run", "--rm", "--network", "none",
                 "-v", str(tmp) + ":/check:ro",
                 "-v", str(cert_dir) + ":/etc/sing-box/tls:ro",
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
