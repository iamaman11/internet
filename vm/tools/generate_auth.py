#!/usr/bin/env python3
"""Generate a new INTERNET VM auth bundle for direct capture by secret-vault.

NEVER invoke in an interactive terminal or CI: stdout contains private data.
Usage: secret-vault capture ... -- python3 vm/tools/generate_auth.py
"""
import base64
import json
import secrets
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def reality_private():
    private = X25519PrivateKey.generate().private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    return base64.urlsafe_b64encode(private).rstrip(b"=").decode("ascii")


def generate():
    return {
        "schema": "internet-vm-auth-v1",
        "vless_direct_uuid": str(uuid.uuid4()),
        "vless_warp_uuid": str(uuid.uuid4()),
        "hy2_direct_password": secrets.token_urlsafe(36),
        "hy2_warp_password": secrets.token_urlsafe(36),
        "proxy_user": "internet",
        "proxy_password": secrets.token_urlsafe(36),
        "reality_direct_private": reality_private(),
        "reality_warp_private": reality_private(),
        "reality_direct_short_id": secrets.token_hex(8),
        "reality_warp_short_id": secrets.token_hex(8),
    }


if __name__ == "__main__":
    print(json.dumps(generate(), separators=(",", ":")))
