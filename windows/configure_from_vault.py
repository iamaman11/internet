#!/usr/bin/env python3
"""Translate existing INTERNET VM Vault bundle into a native Windows sing-box config.

Trusted child of secret-vault run-file only; no new secret store, output never
printed. The Rust INTERNET CLI exclusively validates and persists native JSON.
"""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

SRC = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SRC / "vm" / "tools"))
from render_runtime import validate

VM_IP = "64.176.74.102"
REALITY_SNI = "www.cloudflare.com"
DOMAIN = "miu.alegria.by"
ROUTES = [
    "direct-auto", "direct-hysteria2", "direct-vless",
    "warp-auto", "warp-hysteria2", "warp-vless",
]


def public_key(private_b64):
    key = X25519PrivateKey.from_private_bytes(
        base64.urlsafe_b64decode(private_b64 + "=" * (-len(private_b64) % 4))
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.urlsafe_b64encode(public).rstrip(b"=").decode("ascii")


def build(auth):
    validate(auth)
    outbounds = []
    for mode, port, name in (("direct", 443, "vless"), ("warp", 5443, "vless")):
        outbounds.append({
            "type": "vless", "tag": f"{mode}-{name}",
            "server": VM_IP, "server_port": port,
            "uuid": auth[f"vless_{mode}_uuid"],
            "flow": "xtls-rprx-vision",
            "tls": {
                "enabled": True, "server_name": REALITY_SNI,
                "utls": {"enabled": True, "fingerprint": "chrome"},
                "reality": {
                    "enabled": True,
                    "public_key": public_key(auth[f"reality_{mode}_private"]),
                    "short_id": auth[f"reality_{mode}_short_id"],
                },
            },
        })
    for mode, port in (("direct", 8443), ("warp", 9444)):
        outbounds.append({
            "type": "hysteria2", "tag": f"{mode}-hysteria2",
            "server": VM_IP, "server_port": port,
            "password": auth[f"hy2_{mode}_password"],
            "tls": {"enabled": True, "server_name": DOMAIN, "alpn": ["h3"]},
        })
    for mode in ("direct", "warp"):
        outbounds.append({
            "type": "urltest", "tag": f"{mode}-auto",
            "outbounds": [f"{mode}-hysteria2", f"{mode}-vless"],
            "url": "https://www.gstatic.com/generate_204",
            "interval": "5m",
        })
    for target in ("desktop", "wsl"):
        outbounds.append({
            "type": "selector", "tag": f"{target}-selector",
            "outbounds": ROUTES, "default": "direct-auto",
        })
    return {
        "log": {"level": "warn", "timestamp": True},
        "dns": {"servers": [{"type": "local", "tag": "local-dns"}], "final": "local-dns"},
        "inbounds": [
            {"type": "mixed", "tag": "desktop-in", "listen": "127.0.0.1", "listen_port": 2080},
            {"type": "mixed", "tag": "wsl-in", "listen": "127.0.0.1", "listen_port": 2081,
             "users": [{"username": auth["proxy_user"], "password": auth["proxy_password"]}]},
        ],
        "outbounds": outbounds,
        "route": {
            "rules": [
                {"inbound": ["desktop-in"], "outbound": "desktop-selector"},
                {"inbound": ["wsl-in"], "outbound": "wsl-selector"},
            ],
            "final": "desktop-selector",
            "default_domain_resolver": "local-dns",
        },
        "experimental": {
            "clash_api": {"external_controller": "127.0.0.1:9090"},
        },
    }


def main():
    source = os.environ.get("INTERNET_VM_AUTH_FILE")
    if not source:
        raise RuntimeError("VAULT_BINDING_MISSING")
    auth = json.loads(Path(source).read_text(encoding="utf-8"))
    native = json.dumps(build(auth), separators=(",", ":")).encode("utf-8")
    exe = Path("/mnt/c/internet/internet.exe")
    if not exe.is_file():
        raise RuntimeError("INTERNET_NOT_INSTALLED")
    result = subprocess.run(
        [str(exe), "configure", "--stdin", "--json"],
        input=native, capture_output=True, timeout=30,
    )
    # Never print child stdout/stderr (it might contain sensitive input).
    if result.returncode:
        print("WINDOWS_CONFIGURE_FAILED")
        raise SystemExit(result.returncode)
    print("WINDOWS_NATIVE_CONFIGURE=CODE_PASS")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, OSError, KeyError, subprocess.TimeoutExpired):
        print("WINDOWS_CONFIGURE_FAILED")
        raise SystemExit(1) from None
