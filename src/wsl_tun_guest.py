"""INTERNET WSL native guest adapter. Invoked only by the Rust CLI, never a service."""
import json
import os
import pathlib
import subprocess
import sys

IFACE = "internet-wsl"
IP = "10.222.28.2/30"
KEY_FILE = "/etc/wireguard/internet-wsl.key"
PORT = "43912"
TABLE = "163"
LOCAL_RULE = "163"
TUNNEL_RULE = "164"
ORIGINAL_RESOLV = "/mnt/wsl/resolv.conf"
STUB_RESOLV = "/run/systemd/resolve/stub-resolv.conf"

def run(*args, check=True):
    p = subprocess.run(args, capture_output=True, text=True, timeout=20)
    if check and p.returncode:
        raise RuntimeError("NATIVE_GUEST_COMMAND_FAILED")
    return p

def sudo(*args, check=True):
    return run("/usr/bin/sudo", "-n", *args, check=check)

def rule_lines():
    return run("/usr/sbin/ip", "-4", "rule", "show").stdout.splitlines()

def owned_rules():
    a = [s for s in rule_lines() if s.startswith("163:")]
    b = [s for s in rule_lines() if s.startswith("164:")]
    return (
        len(a) == 1 and "lookup main" in a[0] and "suppress_prefixlength 0" in a[0],
        len(b) == 1 and ("lookup 163" in b[0] or "lookup internet-wsl" in b[0]),
        bool(a or b),
    )

def interface_exists():
    return pathlib.Path("/sys/class/net", IFACE).exists()

def assert_owned(public=None):
    if not interface_exists():
        raise RuntimeError("WSL_WG_INTERFACE_NOT_FOUND")
    addresses = run("/usr/sbin/ip", "-4", "-o", "addr", "show", "dev", IFACE).stdout
    if IP not in addresses:
        raise RuntimeError("WSL_WG_INTERFACE_UNOWNED")
    listen = sudo("/usr/bin/wg", "show", IFACE, "listen-port").stdout.strip()
    if listen != PORT:
        raise RuntimeError("WSL_WG_LISTEN_UNOWNED")
    if public and sudo("/usr/bin/wg", "show", IFACE, "public-key").stdout.strip() != public:
        raise RuntimeError("WSL_WG_KEY_UNOWNED")

def dns_target():
    p = pathlib.Path("/etc/resolv.conf")
    return os.readlink(p) if p.is_symlink() else "NOT_SYMLINK"

def route_state():
    own_main, own_table, any_rules = owned_rules()
    route = run("/usr/sbin/ip", "-4", "route", "show", "table", TABLE, check=False).stdout.splitlines()
    exact = len(route) == 1 and route[0].strip() == "default dev " + IFACE + " scope link"
    ipv6 = run("/usr/sbin/ip", "-6", "route", "show", "default").stdout
    guard = "unreachable default" in ipv6 and "metric 1" in ipv6
    handshake = False
    if interface_exists():
        import time
        raw = sudo("/usr/bin/wg", "show", IFACE, "latest-handshakes").stdout.strip()
        handshake = any(0 < int(x) <= time.time() and time.time()-int(x) < 180
                        for x in raw.split() if x.isdigit())
    eth = run("/usr/sbin/ip", "-4", "-o", "addr", "show", "dev", "eth0").stdout.split()
    guest_ip = eth[3].split("/")[0] if len(eth) >= 4 and eth[2] == "inet" else "UNKNOWN"
    return dict(guest_ipv4=guest_ip, kernel_interface=interface_exists(), handshake_observed=handshake, route_active=own_main and own_table and exact,
                owned_route_rules=any_rules, dns_redirected=dns_target() == STUB_RESOLV,
                ipv6_guard=guard, unexpected_route=bool(route) and not exact,
                default_nat=run("/usr/sbin/ip", "-4", "route", "show", "default").stdout.strip())

def prepare(public):
    if len(public) != 44:
        raise RuntimeError("WSL_WG_PUBLIC_INVALID")
    if interface_exists():
        assert_owned()
        raise RuntimeError("WSL_WG_ALREADY_PRESENT")
    if owned_rules()[2]:
        raise RuntimeError("WSL_WG_ORPHAN_RULE")
    # Native root-only working key. Provisioning/recovery is outside runtime.
    meta = sudo("/usr/bin/stat", "-c", "%u:%a", KEY_FILE, check=False)
    if meta.returncode or meta.stdout.strip() != "0:600":
        raise RuntimeError("WSL_GUEST_KEY_NOT_PROVISIONED")
    try:
        sudo("/usr/sbin/ip", "link", "add", IFACE, "type", "wireguard")
        sudo("/usr/sbin/ip", "address", "add", IP, "dev", IFACE)
        sudo("/usr/bin/wg", "set", IFACE, "listen-port", PORT,
             "private-key", KEY_FILE, "peer", public, "allowed-ips", "0.0.0.0/0")
        sudo("/usr/sbin/ip", "link", "set", "dev", IFACE, "mtu", "1220", "up")
        assert_owned()
        print(json.dumps({"ok": True, "phase": "guest_prepared", "default_route_unchanged": True}))
    except Exception:
        sudo("/usr/sbin/ip", "link", "del", IFACE, check=False)
        raise

def activate(public):
    assert_owned(public)
    state = route_state()
    if state["route_active"] and state["dns_redirected"] and state["ipv6_guard"]:
        print(json.dumps({"ok": True, "changed": False, "phase": "already_active"}))
        return
    if (state["owned_route_rules"] or state["unexpected_route"] or state["dns_redirected"]
            or state["ipv6_guard"]):
        raise RuntimeError("WSL_WG_PARTIAL_STATE_REFUSE")
    if dns_target() != ORIGINAL_RESOLV:
        raise RuntimeError("WSL_RESOLV_OWNER_CONFLICT")
    if not pathlib.Path(STUB_RESOLV).is_file():
        raise RuntimeError("WSL_RESOLVED_STUB_MISSING")
    if run("/usr/sbin/ip", "-6", "route", "show", "default").stdout.strip():
        raise RuntimeError("WSL_IPV6_DEFAULT_CONFLICT")
    if not run("/usr/bin/systemctl", "is-active", "systemd-resolved", check=False).returncode == 0:
        raise RuntimeError("WSL_RESOLVED_NOT_ACTIVE")
    try:
        sudo("/usr/sbin/ip", "-4", "route", "add", "default", "dev", IFACE, "table", TABLE)
        sudo("/usr/sbin/ip", "-4", "rule", "add", "priority", LOCAL_RULE, "lookup",
             "main", "suppress_prefixlength", "0")
        sudo("/usr/sbin/ip", "-4", "rule", "add", "priority", TUNNEL_RULE, "lookup", TABLE)
        sudo("/usr/sbin/ip", "-6", "route", "add", "unreachable", "default", "metric", "1")
        sudo("/usr/bin/resolvectl", "dns", IFACE, "1.1.1.1", "8.8.8.8")
        sudo("/usr/bin/resolvectl", "domain", IFACE, "~.")
        sudo("/usr/bin/resolvectl", "default-route", IFACE, "yes")
        # WSL owns the original resolver symlink; restore it exactly on OFF.
        sudo("/usr/bin/ln", "-sfn", STUB_RESOLV, "/etc/resolv.conf")
        state = route_state()
        if not (state["route_active"] and state["dns_redirected"] and state["ipv6_guard"]):
            raise RuntimeError("WSL_WG_APPLY_READBACK_FAILED")
        print(json.dumps({"ok": True, "changed": True, "phase": "guest_full_route_active"}))
    except Exception:
        # Only own address, rule priorities and exact resolver symlink are touched.
        if dns_target() == STUB_RESOLV:
            sudo("/usr/bin/ln", "-sfn", ORIGINAL_RESOLV, "/etc/resolv.conf", check=False)
        sudo("/usr/bin/resolvectl", "revert", IFACE, check=False)
        sudo("/usr/sbin/ip", "-6", "route", "del", "unreachable", "default",
             "metric", "1", check=False)
        sudo("/usr/sbin/ip", "-4", "rule", "del", "priority", TUNNEL_RULE,
             check=False)
        sudo("/usr/sbin/ip", "-4", "rule", "del", "priority", LOCAL_RULE,
             check=False)
        sudo("/usr/sbin/ip", "-4", "route", "del", "default", "dev", IFACE,
             "table", TABLE, check=False)
        raise

def deactivate(public):
    if not interface_exists():
        if owned_rules()[2] or dns_target() == STUB_RESOLV:
            raise RuntimeError("WSL_WG_ORPHAN_STATE")
        print(json.dumps({"ok": True, "changed": False, "phase": "already_off"}))
        return
    assert_owned(public)
    state = route_state()
    if state["unexpected_route"] or (state["owned_route_rules"] and not state["route_active"]):
        raise RuntimeError("WSL_WG_UNOWNED_ROUTE_REFUSE")
    if dns_target() not in (ORIGINAL_RESOLV, STUB_RESOLV):
        raise RuntimeError("WSL_RESOLV_OWNER_CONFLICT")
    if state["dns_redirected"]:
        sudo("/usr/bin/ln", "-sfn", ORIGINAL_RESOLV, "/etc/resolv.conf")
        sudo("/usr/bin/resolvectl", "revert", IFACE, check=False)
    if state["route_active"]:
        sudo("/usr/sbin/ip", "-4", "rule", "del", "priority", TUNNEL_RULE)
        sudo("/usr/sbin/ip", "-4", "rule", "del", "priority", LOCAL_RULE)
        sudo("/usr/sbin/ip", "-4", "route", "del", "default", "dev", IFACE, "table", TABLE)
    if state["ipv6_guard"]:
        sudo("/usr/sbin/ip", "-6", "route", "del", "unreachable", "default", "metric", "1")
    sudo("/usr/sbin/ip", "link", "del", IFACE)
    print(json.dumps({"ok": True, "changed": True, "phase": "guest_native_off"}))

def main():
    if len(sys.argv) < 2:
        raise RuntimeError("WSL_WG_ACTION_REQUIRED")
    action = sys.argv[1]
    if action == "pubkey":
        meta = sudo("/usr/bin/stat", "-c", "%u:%a", KEY_FILE, check=False)
        if meta.returncode or meta.stdout.strip() != "0:600":
            raise RuntimeError("WSL_GUEST_KEY_NOT_PROVISIONED")
        key = sudo("/usr/bin/sh", "-c", "/usr/bin/wg pubkey < /etc/wireguard/internet-wsl.key").stdout.strip()
        if len(key) != 44 or not key.endswith("="):
            raise RuntimeError("WSL_GUEST_PUBLIC_INVALID")
        print(json.dumps({"ok": True, "public_key": key}))
    elif action == "status":
        state = route_state()
        state["ok"] = True
        state["dns_target_kind"] = ("wsl_generated" if dns_target() == ORIGINAL_RESOLV
                                     else "resolved_stub" if dns_target() == STUB_RESOLV
                                     else "unknown")
        print(json.dumps(state))
    elif action == "prepare" and len(sys.argv) == 3:
        prepare(sys.argv[2])
    elif action == "activate" and len(sys.argv) == 3:
        activate(sys.argv[2])
    elif action == "off" and len(sys.argv) == 3:
        deactivate(sys.argv[2])
    else:
        raise RuntimeError("WSL_WG_ACTION_INVALID")

try:
    main()
except (RuntimeError, subprocess.TimeoutExpired, OSError) as error:
    # Never relay arbitrary stderr, private keys or tool internals.
    code = str(error) if isinstance(error, RuntimeError) else "WSL_NATIVE_IO_FAILED"
    print(json.dumps({"ok": False, "reason_code": code}))
    sys.exit(4)
