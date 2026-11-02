"""Native sing-box 1.14.2 Linux image checks: actual config, disposable secrets, no network."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "vm" / "tools"))
from configure_from_vault import build
from generate_auth import generate

ROOT = Path(__file__).resolve().parents[2]
IMAGE_ENV = ROOT / "vm" / "images.env.example"


def image_ref():
    for line in IMAGE_ENV.read_text().splitlines():
        if line.startswith("INTERNET_SING_BOX_IMAGE="):
            ref = line.split("=", 1)[1].strip()
            if "@sha256:" in ref:
                return ref
    raise RuntimeError("PINNED_IMAGE_NOT_FOUND")


def main():
    config = build(generate())
    with tempfile.TemporaryDirectory(prefix="internet-s2-native-") as directory:
        path = Path(directory) / "config.json"
        path.write_text(json.dumps(config))
        os.chmod(path, 0o600)
        cmd = ["docker", "run", "--rm", "--pull=always", "--network", "none",
               "-v", f"{path}:/etc/sing-box/config.json:ro",
               image_ref(), "check", "-c", "/etc/sing-box/config.json"]
        r = subprocess.run(cmd, capture_output=True, timeout=100)
        if r.returncode:
            print("S2_NATIVE_SING_BOX_CONFIG_FAILED")
            raise SystemExit(1)
    print("S2_NATIVE_SING_BOX_CONFIG_PASS")


if __name__ == "__main__":
    main()
