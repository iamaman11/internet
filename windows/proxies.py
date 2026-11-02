#!/usr/bin/env python3
"""Trusted, stateless Vault consumer. No credentials in argv, logs or saved files."""
import concurrent.futures
import ipaddress
import json
import os
import subprocess
import sys
import time

PORTS = (
    ("DIRECT", "HTTP", 4128, "http"),
    ("DIRECT", "SOCKS5", 4080, "socks5h"),
    ("DIRECT", "HTTPS", 4443, "https"),
    ("WARP", "HTTP", 3128, "http"),
    ("WARP", "SOCKS5", 1080, "socks5h"),
    ("WARP", "HTTPS", 9443, "https"),
)

def load_credentials():
    source = os.environ.get("INTERNET_VM_AUTH_FILE", "")
    if not source:
        raise ValueError("VAULT_FILE_BINDING_MISSING")
    with open(source, encoding="utf-8") as f:
        obj = json.load(f)
    if obj.get("schema") != "internet-vm-auth-v1":
        raise ValueError("VAULT_SCHEMA_INVALID")
    for key in ("proxy_user", "proxy_password"):
        v = obj.get(key)
        if not isinstance(v, str) or not v or any(ord(c) < 32 for c in v):
            raise ValueError("VAULT_AUTH_FIELD_INVALID")
    return obj["proxy_user"], obj["proxy_password"]

def curl_config(user, password):
    # JSON quoting is compatible with curl's double-quoted config grammar;
    # reject line/control injection before putting the value on private stdin.
    return "proxy-user = " + json.dumps(user + ":" + password, ensure_ascii=True) + "\n"

def probe(item, ip, domain, auth):
    mode, protocol, port, scheme = item
    host = domain if scheme == "https" else ip
    url = f"{scheme}://{host}:{port}"
    args = ["curl", "-4", "--silent", "--fail", "--noproxy", "",
            "--proxy", url, "--connect-timeout", "4", "--max-time", "10",
            "-K", "-", "https://api.ipify.org"]
    if scheme == "https":
        args[1:1] = ["--resolve", f"{domain}:{port}:{ip}"]
    started = time.monotonic()
    try:
        p = subprocess.run(args, input=auth, text=True, capture_output=True, timeout=12)
        value = p.stdout.strip()
        if p.returncode != 0:
            status, reason = "FAILED", f"CURL_EXIT_{p.returncode}"
        else:
            try:
                addr = ipaddress.IPv4Address(value)
                if not addr.is_global:
                    raise ValueError("not public")
                status, reason = ("PASS", "VM_IP_CONFIRMED") if (mode == "DIRECT" and value == ip) else (("PASS", "DIFFERENT_PUBLIC_EGRESS") if mode == "WARP" and value != ip else ("FAILED", "EGRESS_IP_UNEXPECTED"))
            except ValueError:
                status, reason = "FAILED", "PUBLIC_IPV4_INVALID"
        return dict(mode=mode, protocol=protocol, port=port, endpoint=url,
                    status=status, exit_ip=value if status == "PASS" else None,
                    duration_ms=round((time.monotonic()-started)*1000), reason_code=reason)
    except (subprocess.TimeoutExpired, OSError):
        return dict(mode=mode, protocol=protocol, port=port, endpoint=url,
                    status="UNKNOWN", exit_ip=None,
                    duration_ms=round((time.monotonic()-started)*1000), reason_code="PROBE_TIMEOUT_OR_UNAVAILABLE")

def main():
    if len(sys.argv) != 4 or sys.argv[1] not in ("show", "test"):
        raise ValueError("OPERATION_UNSUPPORTED")
    mode, rawip, domain = sys.argv[1:]
    ip = str(ipaddress.IPv4Address(rawip))
    if not ipaddress.IPv4Address(ip).is_global:
        raise ValueError("VM_IP_UNSAFE")
    if not domain or len(domain) > 253 or not all(x and x.replace("-", "").isalnum() for x in domain.split(".")):
        raise ValueError("TLS_DOMAIN_INVALID")
    user, password = load_credentials()
    if mode == "show":
        print("VM:", ip)
        print("HTTPS TLS name:", domain)
        print("LOGIN:", user)
        print("PASSWORD:", password)
        print("6 endpoints use the same credentials.")
        return 0
    private = curl_config(user, password)
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        items = list(pool.map(lambda item: probe(item, ip, domain, private), PORTS))
    count = sum(x["status"] == "PASS" for x in items)
    print(json.dumps({"ok": count == 6, "scope": "live_ipv4_https_egress_via_6_authenticated_tcp_proxies",
                      "pass": count, "total": 6, "results": items}, separators=(",", ":")))
    return 0 if count == 6 else 3

if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, KeyError, OSError, json.JSONDecodeError):
        print("PROXY_VAULT_CONSUMER_FAILED", file=sys.stderr)
        sys.exit(4)
