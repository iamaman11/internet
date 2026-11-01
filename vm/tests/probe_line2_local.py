#!/usr/bin/env python3
"""S1 physical Line2 probe on the VM: 6 endpoints, auth rejection, actual egress.

Reads the already-installed root-only runtime config. Never prints credentials
or includes them in argv, environment, logs or Git. No state changes.
Not part of CI: this is a live network probe on the exact VM.
"""
import argparse
import base64
import ipaddress
import json
from pathlib import Path
import socket
import ssl
import sys

CONFIG = Path("/opt/internet/vm/runtime/line2.json")
TARGET = "api.ipify.org"
DIRECT_IP = "64.176.74.102"
TLS_NAME = "miu.alegria.by"
PORTS = (
    ("http-warp", "http", 3128, "warp"),
    ("socks-warp", "socks", 1080, "warp"),
    ("https-warp", "https", 9443, "warp"),
    ("http-direct", "http", 4128, "direct"),
    ("socks-direct", "socks", 4080, "direct"),
    ("https-direct", "https", 4443, "direct"),
)


class ProbeError(Exception):
    pass


def exactly(conn, size):
    data = b""
    while len(data) < size:
        piece = conn.recv(size - len(data))
        if not piece:
            raise ProbeError("TRUNCATED_REPLY")
        data += piece
    return data


def http_response(conn):
    reply = b""
    while len(reply) < 32768:
        part = conn.recv(4096)
        if not part:
            break
        reply += part
    head, marker, body = reply.partition(b"\r\n\r\n")
    if not marker or not head.startswith(b"HTTP/"):
        raise ProbeError("HTTP_REPLY_INVALID")
    try:
        status = int(head.split(b" ", 2)[1])
    except (IndexError, ValueError) as exc:
        raise ProbeError("HTTP_STATUS_INVALID") from exc
    if b"transfer-encoding: chunked" in head.lower():
        chunks = []
        while body:
            size_line, delim, tail = body.partition(b"\r\n")
            if not delim:
                raise ProbeError("HTTP_CHUNK_INVALID")
            try:
                size = int(size_line.split(b";", 1)[0], 16)
            except ValueError as exc:
                raise ProbeError("HTTP_CHUNK_INVALID") from exc
            if size == 0:
                break
            if len(tail) < size + 2:
                raise ProbeError("HTTP_CHUNK_TRUNCATED")
            chunks.append(tail[:size])
            body = tail[size + 2:]
        body = b"".join(chunks)
    return status, body


def public_ip(body):
    try:
        value = ipaddress.ip_address(body.decode("ascii").strip())
    except (UnicodeError, ValueError) as exc:
        raise ProbeError("EGRESS_REPLY_NOT_IP") from exc
    if not value.is_global or value.version != 4:
        raise ProbeError("EGRESS_IP_NOT_PUBLIC_IPV4")
    return str(value)


def http_proxy(port, scheme, user, password, negative=False):
    with socket.create_connection(("127.0.0.1", port), timeout=12) as conn:
        conn.settimeout(12)
        if scheme == "https":
            ctx = ssl.create_default_context()
            ctx.set_alpn_protocols(["http/1.1"])
            conn = ctx.wrap_socket(conn, server_hostname=TLS_NAME)
            if conn.selected_alpn_protocol() not in (None, "http/1.1"):
                raise ProbeError("TLS_ALPN_UNEXPECTED")
        pwd = "intentionally-invalid" if negative else password
        encoded = base64.b64encode((user + ":" + pwd).encode("utf-8")).decode("ascii")
        request = (
            "GET http://" + TARGET + "/ HTTP/1.1\r\n"
            "Host: " + TARGET + "\r\n"
            "Proxy-Authorization: Basic " + encoded + "\r\n"
            "Connection: close\r\n\r\n"
        )
        conn.sendall(request.encode("ascii"))
        status, body = http_response(conn)
        if negative:
            if status != 407:
                raise ProbeError("BAD_AUTH_ACCEPTED_OR_WRONG_STATUS_" + str(status))
            return "AUTH_REJECTED"
        if status != 200:
            raise ProbeError("UPSTREAM_HTTP_STATUS_" + str(status))
        return public_ip(body)


def socks_proxy(port, user, password, negative=False):
    with socket.create_connection(("127.0.0.1", port), timeout=12) as conn:
        conn.settimeout(12)
        conn.sendall(b"\x05\x01\x02")
        if exactly(conn, 2) != b"\x05\x02":
            raise ProbeError("SOCKS_AUTH_METHOD_UNEXPECTED")
        ub = user.encode("utf-8")
        pb = ("intentionally-invalid" if negative else password).encode("utf-8")
        if not (1 <= len(ub) <= 255 and 1 <= len(pb) <= 255):
            raise ProbeError("SOCKS_CREDENTIAL_LENGTH_INVALID")
        conn.sendall(bytes([1, len(ub)]) + ub + bytes([len(pb)]) + pb)
        reply = exactly(conn, 2)
        if negative:
            if reply == b"\x01\x00":
                raise ProbeError("BAD_AUTH_ACCEPTED")
            return "AUTH_REJECTED"
        if reply != b"\x01\x00":
            raise ProbeError("VALID_AUTH_REJECTED")
        name = TARGET.encode("ascii")
        conn.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + b"\x00\x50")
        reply = exactly(conn, 4)
        if reply[:2] != b"\x05\x00":
            raise ProbeError("SOCKS_CONNECT_REJECTED_" + str(reply[1]))
        atyp = reply[3]
        if atyp == 1:
            exactly(conn, 4)
        elif atyp == 4:
            exactly(conn, 16)
        elif atyp == 3:
            exactly(conn, exactly(conn, 1)[0])
        else:
            raise ProbeError("SOCKS_BOUND_ADDR_INVALID")
        exactly(conn, 2)
        conn.sendall(("GET / HTTP/1.1\r\nHost: " + TARGET + "\r\nConnection: close\r\n\r\n").encode("ascii"))
        status, body = http_response(conn)
        if status != 200:
            raise ProbeError("UPSTREAM_HTTP_STATUS_" + str(status))
        return public_ip(body)


def credentials():
    cfg = json.loads(CONFIG.read_text(encoding="utf-8"))
    users = {}
    for inbound in cfg.get("inbounds", ()):
        tag = inbound.get("tag")
        configured = inbound.get("users", ())
        if len(configured) != 1:
            raise ProbeError("INBOUND_USERS_NOT_EXACTLY_ONE")
        item = configured[0]
        if not item.get("username") or not item.get("password"):
            raise ProbeError("INBOUND_CREDENTIAL_MISSING")
        users[tag] = (item["username"], item["password"])
    expected = {
        "http-proxy-auth": 3128, "socks-proxy-auth": 1080,
        "https-proxy-auth": 9443, "http-proxy-direct-auth": 4128,
        "socks-proxy-direct-auth": 4080, "https-proxy-direct-auth": 4443,
    }
    if len(users) != 6 or set(users) != set(expected):
        raise ProbeError("INBOUND_COUNT_OR_TAG_MISMATCH")
    return users


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ports", default="3128,1080,9443,4128,4080,4443")
    args = parser.parse_args()
    selected = {int(port) for port in args.ports.split(",")}
    if selected - {entry[2] for entry in PORTS}:
        raise ProbeError("UNKNOWN_PORT")
    users = credentials()
    status = {}
    for name, scheme, port, route in PORTS:
        if port not in selected:
            continue
        tag = name.replace("http-warp", "http-proxy-auth").replace("socks-warp", "socks-proxy-auth").replace("https-warp", "https-proxy-auth").replace("http-direct", "http-proxy-direct-auth").replace("socks-direct", "socks-proxy-direct-auth").replace("https-direct", "https-proxy-direct-auth")
        user, password = users[tag]
        probe = socks_proxy if scheme == "socks" else lambda port_, u, p, negative=False: http_proxy(port_, scheme, u, p, negative)
        try:
            denied = probe(port, user, password, negative=True)
            ip = probe(port, user, password)
            if route == "direct" and ip != DIRECT_IP:
                raise ProbeError("DIRECT_IP_MISMATCH")
            if route == "warp" and ip == DIRECT_IP:
                raise ProbeError("WARP_FELL_BACK_TO_DIRECT")
            status[name] = ("PASS", ip, denied)
            print(name + "=PASS egress=" + ip + " negative_auth=" + denied, flush=True)
        except (ProbeError, OSError, ssl.SSLError, ValueError) as exc:
            reason = str(exc) if isinstance(exc, ProbeError) else type(exc).__name__
            print(name + "=FAILED reason=" + reason, flush=True)
            status[name] = ("FAILED", None, None)
    print("SUMMARY=" + str(sum(1 for r in status.values() if r[0] == "PASS")) + "/" + str(len(selected)))
    return 0 if all(x[0] == "PASS" for x in status.values()) and len(status) == len(selected) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, ProbeError) as exc:
        print("PROBE_FATAL=" + (str(exc) if isinstance(exc, ProbeError) else type(exc).__name__))
        sys.exit(2)
