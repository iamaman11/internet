#!/usr/bin/env python3
"""Render S1 sing-box configs from an existing secret-vault run-file binding.

Vault only passes the file path in INTERNET_VM_AUTH_FILE. Never print the
payload, store it in Git, or accept secret values via command-line arguments.
"""
import json
import os
from pathlib import Path
import re
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
PLACEHOLDER = re.compile(r"\$\{([A-Z][A-Z0-9_]*)\}")
KEYS = {
    "vless_direct_uuid": "VLESS_UUID",
    "vless_warp_uuid": "VLESS_WARP_UUID",
    "hy2_direct_password": "HY2_PASSWORD",
    "hy2_warp_password": "HY2_WARP_PASSWORD",
    "proxy_user": "PROXY_USERNAME",
    "proxy_password": "PROXY_PASSWORD",
    "reality_direct_private": "REALITY_PRIVATE_KEY",
    "reality_warp_private": "REALITY_WARP_PRIVATE_KEY",
    "reality_direct_short_id": "REALITY_SHORT_ID",
    "reality_warp_short_id": "REALITY_WARP_SHORT_ID",
}
B64URL = re.compile(r"[A-Za-z0-9_-]{43}")
SHORT_ID = re.compile(r"[a-f0-9]{16}")


def validate(payload):
    if not isinstance(payload, dict) or payload.get("schema") != "internet-vm-auth-v1":
        raise ValueError("AUTH_SCHEMA_INVALID")
    if set(payload) != set(KEYS) | {"schema"}:
        raise ValueError("AUTH_FIELDS_MISMATCH")
    for name in KEYS:
        if not isinstance(payload[name], str) or not payload[name]:
            raise ValueError("AUTH_FIELD_INVALID:" + name)
    for name in ("vless_direct_uuid", "vless_warp_uuid"):
        if str(uuid.UUID(payload[name])) != payload[name]:
            raise ValueError("AUTH_UUID_INVALID")
    for name in ("reality_direct_private", "reality_warp_private"):
        if not B64URL.fullmatch(payload[name]):
            raise ValueError("AUTH_REALITY_INVALID")
    for name in ("reality_direct_short_id", "reality_warp_short_id"):
        if not SHORT_ID.fullmatch(payload[name]):
            raise ValueError("AUTH_SHORT_ID_INVALID")
    if len(payload["proxy_password"]) < 24 or len(payload["hy2_direct_password"]) < 24 or len(payload["hy2_warp_password"]) < 24:
        raise ValueError("AUTH_PASSWORD_TOO_SHORT")


def render(template, values):
    expected = set(PLACEHOLDER.findall(template))
    if expected - values.keys():
        raise ValueError("TEMPLATE_REQUIRED_FIELD_MISSING")
    rendered = PLACEHOLDER.sub(lambda match: values[match.group(1)], template)
    if PLACEHOLDER.search(rendered):
        raise ValueError("UNRESOLVED_PLACEHOLDER")
    return json.dumps(json.loads(rendered), indent=2) + "\n"


def prepare(payload, domain, reality_server):
    validate(payload)
    if not isinstance(domain, str) or not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", domain) or "." not in domain:
        raise ValueError("TUNNEL_DOMAIN_INVALID")
    if not isinstance(reality_server, str) or not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", reality_server):
        raise ValueError("REALITY_SERVER_INVALID")
    values = {var: payload[key] for key, var in KEYS.items()}
    values["TUNNEL_DOMAIN"] = domain
    values["REALITY_SERVER_NAME"] = reality_server
    result = {}
    for name in ("line1", "line2"):
        result[name + ".json"] = render((ROOT / "templates" / (name + ".json")).read_text(encoding="utf-8"), values)
    return result


def write_private(directory, files):
    directory = Path(directory)
    if directory.is_symlink():
        raise ValueError("RUNTIME_PATH_SYMLINK")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    for filename, contents in files.items():
        target = directory / filename
        if target.is_symlink():
            raise ValueError("CONFIG_PATH_SYMLINK")
        fd, tmp = tempfile.mkstemp(prefix=".incoming-", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as out:
                out.write(contents)
            os.chmod(tmp, 0o600)
            os.replace(tmp, target)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)


def main():
    path = os.environ.get("INTERNET_VM_AUTH_FILE")
    domain = os.environ.get("INTERNET_TUNNEL_DOMAIN")
    server = os.environ.get("INTERNET_REALITY_SERVER")
    output = os.environ.get("INTERNET_RUNTIME_DIR")
    if not all((path, domain, server, output)):
        raise ValueError("RENDER_INPUT_MISSING")
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    files = prepare(payload, domain, server)
    write_private(output, files)
    print("RENDER_COMPLETE:line1,line2")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        # Never log exception details: an exception may embed secret contents.
        print("RENDER_FAILED")
        raise SystemExit(1) from None
