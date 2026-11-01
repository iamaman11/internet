#!/usr/bin/env python3
"""S1 read-only Line1 physical probe: four real sing-box client paths.

Run as root on the exact VM. It reads the installed private Line1 config,
derives Reality public keys in memory, and starts one disposable native
sing-box client at a time. Only ephemeral Docker containers and temp files
are created; production containers, configuration and routes are untouched.
No secret values, config contents or subprocess stderr are printed.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from install_vm import line2_image
from render_runtime import prepare
from probe_line2_local import http_response, public_ip

CONFIG = Path("/opt/internet/vm/runtime/line1.json")
TARGET = "api.ipify.org"
DIRECT_IP = "64.176.74.102"
CA_NAME = "miu.alegria.by"
REMOTE_SERVER = "64.176.74.102"
REALITY_NAME = "www.cloudflare.com"
SPECS = (
    ("vless-reality-main", "vless", 443, "direct"),
    ("hy2-direct-main", "hysteria2", 8443, "direct"),
    ("vless-reality-warp", "vless", 5443, "warp"),
    ("hy2-warp", "hysteria2", 9444, "warp"),
)


class ProbeError(Exception):
    pass


class InvalidAuthRejected(ProbeError):
    pass


def public_from_private(private):
    try:
        raw = base64.urlsafe_b64decode(private + "=" * (-len(private) % 4))
        if len(raw) != 32:
            raise ValueError()
        key = X25519PrivateKey.from_private_bytes(raw).public_key()
        return base64.urlsafe_b64encode(key.public_bytes(
            Encoding.Raw, PublicFormat.Raw)).decode("ascii").rstrip("=")
    except (ValueError, TypeError) as exc:
        raise ProbeError("REALITY_PRIVATE_KEY_INVALID") from exc


def outbound_for(inbound, *, invalid=False, server="127.0.0.1"):
    kind = inbound["type"]
    port = inbound["listen_port"]
    users = inbound["users"]
    if len(users) != 1:
        raise ProbeError("INBOUND_USERS_UNEXPECTED")
    if kind == "vless":
        reality = inbound["tls"]["reality"]
        public = public_from_private(reality["private_key"])
        uuid = "00000000-0000-4000-8000-000000000000" if invalid else users[0]["uuid"]
        return {
            "type": "vless", "tag": "upstream", "server": server,
            "server_port": port, "uuid": uuid,
            "flow": users[0]["flow"],
            "tls": {
                "enabled": True, "server_name": REALITY_NAME,
                "utls": {"enabled": True, "fingerprint": "chrome"},
                "reality": {"enabled": True, "public_key": public,
                            "short_id": reality["short_id"][0]},
            },
        }
    if kind == "hysteria2":
        return {
            "type": "hysteria2", "tag": "upstream", "server": server,
            "server_port": port,
            "password": "intentionally-invalid" if invalid else users[0]["password"],
            "up_mbps": 10, "down_mbps": 10,
            "tls": {"enabled": True, "server_name": CA_NAME, "alpn": ["h3"]},
        }
    raise ProbeError("INBOUND_KIND_UNSUPPORTED")


def config_for(inbound, proxy_port, *, invalid=False, server="127.0.0.1"):
    return {
        "log": {"level": "error"},
        "inbounds": [{"type": "mixed", "tag": "local", "listen": "127.0.0.1",
                      "listen_port": proxy_port}],
        "outbounds": [outbound_for(inbound, invalid=invalid, server=server)],
        "route": {"final": "upstream"},
    }


def proxy_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def exactly(conn, length):
    data = b""
    while len(data) < length:
        more = conn.recv(length - len(data))
        if not more:
            raise ProbeError("UPSTREAM_CLOSED")
        data += more
    return data


def socks_egress(port):
    with socket.create_connection(("127.0.0.1", port), timeout=10) as conn:
        conn.settimeout(9)
        conn.sendall(b"\x05\x01\x00")
        if exactly(conn, 2) != b"\x05\x00":
            raise ProbeError("CLIENT_SOCKS_METHOD_FAIL")
        target = TARGET.encode("ascii")
        conn.sendall(b"\x05\x01\x00\x03" + bytes([len(target)]) +
                     target + b"\x00\x50")
        response = exactly(conn, 4)
        if response[:2] != b"\x05\x00":
            raise ProbeError("CLIENT_SOCKS_CONNECT_FAIL")
        if response[3] == 1:
            exactly(conn, 4)
        elif response[3] == 4:
            exactly(conn, 16)
        elif response[3] == 3:
            exactly(conn, exactly(conn, 1)[0])
        else:
            raise ProbeError("CLIENT_SOCKS_ADDRESS_INVALID")
        exactly(conn, 2)
        conn.sendall(("GET / HTTP/1.1\r\nHost: " + TARGET +
                      "\r\nConnection: close\r\n\r\n").encode("ascii"))
        status, body = http_response(conn)
        if status != 200:
            raise ProbeError("EGRESS_HTTP_STATUS_INVALID")
        return public_ip(body)


def wait_ready(proc, port):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise ProbeError("EPHEMERAL_CLIENT_EXITED")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.15)
    raise ProbeError("EPHEMERAL_CLIENT_NOT_READY")


def error_kind(raw):
    """Convert untrusted Docker stderr to a fixed diagnostic, never echo secrets."""
    value = raw.lower()
    if b"permission denied" in value:
        return "PERMISSION"
    if b"address already in use" in value:
        return "LISTENER_IN_USE"
    if b"unknown field" in value or b"invalid field" in value:
        return "CONFIG_FIELD"
    if b"no such file or directory" in value:
        return "FILE_MISSING"
    if b"executable file not found" in value:
        return "EXECUTABLE_MISSING"
    if b"failed to create" in value:
        return "CONTAINER_CREATE"
    if b"error response from daemon" in value:
        return "DOCKER_DAEMON"
    return "OTHER"


def run_client(inbound, *, invalid=False, server="127.0.0.1"):
    proxy = proxy_port()
    name = "internet-s1-line1-probe-" + str(os.getpid()) + "-" + str(inbound["listen_port"])
    with tempfile.TemporaryDirectory(prefix="internet-s1-line1-") as tmp:
        folder = Path(tmp)
        path = folder / "config.json"
        path.write_text(json.dumps(config_for(inbound, proxy, invalid=invalid, server=server)),
                        encoding="utf-8")
        os.chmod(path, 0o600)
        args = ["docker", "run", "--rm", "--network", "host", "--name", name,
                "-v", str(folder) + ":/probe:ro", line2_image(),
                "run", "-c", "/probe/config.json"]
        validation = subprocess.run(args[:-3] + ["check", "-c", "/probe/config.json"],
                                    capture_output=True, timeout=20)
        if validation.returncode:
            raise ProbeError("CLIENT_NATIVE_CHECK_FAILED:" + error_kind(validation.stderr))
        proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            try:
                wait_ready(proc, proxy)
            except ProbeError as exc:
                if proc.poll() is not None:
                    _, stderr = proc.communicate(timeout=3)
                    raise ProbeError("EPHEMERAL_CLIENT_EXITED:" +
                                     error_kind(stderr)) from exc
                raise
            try:
                return socks_egress(proxy)
            except (OSError, ProbeError) as exc:
                if invalid:
                    raise InvalidAuthRejected("INVALID_AUTH_BLOCKED") from exc
                raise
        finally:
            if proc.poll() is None:
                proc.terminate()
            try:
                proc.wait(timeout=4)
            except subprocess.TimeoutExpired:
                # Only the unique container of this physical probe can be removed.
                subprocess.run(["docker", "rm", "-f", name],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=12)
                proc.wait(timeout=3)


def read_inbounds(*, from_vault=False):
    if from_vault:
        path = os.environ.get("INTERNET_VM_AUTH_FILE")
        if not path:
            raise ProbeError("VAULT_BINDING_MISSING")
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        config = json.loads(prepare(payload, CA_NAME, REALITY_NAME)["line1.json"])
    else:
        config = json.loads(CONFIG.read_text(encoding="utf-8"))
    inbound_map = {entry["tag"]: entry for entry in config["inbounds"]}
    if len(inbound_map) != 4 or set(inbound_map) != {spec[0] for spec in SPECS}:
        raise ProbeError("LINE1_INBOUND_TAGS_MISMATCH")
    for tag, kind, port, _ in SPECS:
        entry = inbound_map[tag]
        if entry["type"] != kind or entry["listen_port"] != port:
            raise ProbeError("LINE1_INBOUND_PORT_MISMATCH")
    return inbound_map


def fixture_native_check():
    """Only throwaway generated fixtures; stdout may include Docker diagnostics."""
    test_key = X25519PrivateKey.generate()
    private = base64.urlsafe_b64encode(
        test_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    ).decode("ascii").rstrip("=")
    vless = {"type": "vless", "listen_port": 443,
             "users": [{"uuid": str(uuid.uuid4()), "flow": "xtls-rprx-vision"}],
             "tls": {"reality": {"private_key": private, "short_id": ["aabbccdd"]}}}
    hy2 = {"type": "hysteria2", "listen_port": 8443,
           "users": [{"password": "dummy-test-password-not-a-secret"}]}
    overall = True
    for name, inbound in (("vless", vless), ("hysteria2", hy2)):
        with tempfile.TemporaryDirectory(prefix="internet-s1-fixture-") as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(json.dumps(config_for(inbound, 18551)),
                            encoding="utf-8")
            os.chmod(path, 0o600)
            cmd = ["docker", "run", "--rm", "--network", "none",
                   "-v", tmp + ":/probe:ro", line2_image(),
                   "check", "-c", "/probe/config.json"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
            print("FIXTURE_" + name.upper() + "_EXIT=" + str(result.returncode))
            if result.returncode:
                overall = False
                # This command only reads a newly generated, nonproduction fixture.
                # Replace generated credentials even if Docker quotes its config.
                safe = result.stderr.replace(private, "<FIXTURE_PRIVATE>")
                safe = safe.replace(vless["users"][0]["uuid"], "<FIXTURE_UUID>")
                print("FIXTURE_ERROR=" + safe[-1000:].replace("\\n", " | "))
    return 0 if overall else 1


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--ports", default="443,8443,5443,9444")
    p.add_argument("--negative", action="store_true")
    p.add_argument("--from-vault", action="store_true")
    p.add_argument("--fixture-native", action="store_true")
    args = p.parse_args()
    if args.fixture_native:
        return fixture_native_check()
    try:
        selected = {int(v) for v in args.ports.split(",")}
    except ValueError as exc:
        raise ProbeError("PORT_SELECTION_INVALID") from exc
    if not selected or selected - {spec[2] for spec in SPECS}:
        raise ProbeError("PORT_SELECTION_INVALID")
    inbound_map = read_inbounds(from_vault=args.from_vault)
    server = REMOTE_SERVER if args.from_vault else "127.0.0.1"
    passed = 0
    for tag, kind, port, route in SPECS:
        if port not in selected:
            continue
        try:
            ip = run_client(inbound_map[tag], server=server)
            if route == "direct" and ip != DIRECT_IP:
                raise ProbeError("DIRECT_EGRESS_MISMATCH")
            if route == "warp" and ip == DIRECT_IP:
                raise ProbeError("WARP_FALLBACK_TO_DIRECT")
            negative = "NOT_RUN"
            if args.negative:
                try:
                    run_client(inbound_map[tag], invalid=True, server=server)
                except InvalidAuthRejected:
                    negative = "REJECTED"
                else:
                    raise ProbeError("INVALID_AUTH_ACCEPTED")
            passed += 1
            print(tag + "=PASS egress=" + ip + " invalid_auth=" + negative, flush=True)
        except (OSError, ProbeError, TimeoutError, subprocess.SubprocessError) as exc:
            reason = str(exc) if isinstance(exc, ProbeError) else type(exc).__name__
            print(tag + "=FAILED reason=" + reason, flush=True)
    print("SUMMARY=" + str(passed) + "/" + str(len(selected)))
    return 0 if passed == len(selected) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ProbeError, KeyError, ValueError) as exc:
        reason = str(exc) if isinstance(exc, ProbeError) else type(exc).__name__
        print("PROBE_FATAL=" + reason)
        sys.exit(2)
