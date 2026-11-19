"""INTERNET owned one-shot WSL boot handoff. No daemon or Windows task."""

import fcntl
import importlib.util
import ipaddress
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import tempfile
import time

BOOT_SCRIPT = pathlib.Path("/usr/local/libexec/internet-wsl-tun-boot.py")
GUEST_SCRIPT = pathlib.Path("/usr/local/libexec/internet-wsl-tun-guest.py")
WSL_CONF = pathlib.Path("/etc/wsl.conf")
STATE = pathlib.Path("/etc/internet/wsl-tun-desired.json")
LOCK = pathlib.Path("/run/internet-wsl-tun-restore.lock")
RESULT = pathlib.Path("/run/internet-wsl-tun-restore.json")
WINDOWS_CONFIG = pathlib.Path("/mnt/c/internet/config/sing-box.json")
BOOT_COMMAND = "/usr/bin/python3 /usr/local/libexec/internet-wsl-tun-boot.py spawn"
BOOT_LINE = "command=" + BOOT_COMMAND + "\n"


def check_root():
    if os.geteuid() != 0:
        raise RuntimeError("WSL_BOOT_ROOT_REQUIRED")


def safe_existing(path, marker=None):
    if not path.exists() and not path.is_symlink():
        return False
    meta = path.lstat()
    if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or (meta.st_mode & 0o022):
        raise RuntimeError("WSL_BOOT_OWNER_CONFLICT")
    if marker and not path.read_text(encoding="utf-8").startswith(marker):
        raise RuntimeError("WSL_BOOT_OWNER_CONFLICT")
    return True


def put_owned(path, payload, mode):
    if path.is_symlink():
        raise RuntimeError("WSL_BOOT_OWNER_CONFLICT")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink() or path.parent.stat().st_uid != 0:
        raise RuntimeError("WSL_BOOT_OWNER_CONFLICT")
    if path.exists():
        safe_existing(path)
    fd, temp = tempfile.mkstemp(prefix=".internet-wsl-", dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def merge_boot_setting(original):
    """Change exactly the owned [boot] command, keeping every foreign setting."""
    if len(original) > 8192:
        raise RuntimeError("WSL_BOOT_CONF_TOO_LARGE")
    try:
        text = original.decode("utf-8")
    except UnicodeDecodeError:
        raise RuntimeError("WSL_BOOT_CONF_INVALID") from None
    lines = text.splitlines(keepends=True)
    sections = []
    for index, line in enumerate(lines):
        match = re.match(r"^\s*\[\s*([^\]]+)\s*\]\s*(?:[;#].*)?$", line.rstrip("\r\n"))
        if match:
            sections.append((match.group(1).strip().lower(), index))
    boots = [i for name, i in sections if name == "boot"]
    if len(boots) > 1:
        raise RuntimeError("WSL_BOOT_OWNER_CONFLICT")
    if not boots:
        ending = "" if not text or text.endswith("\n") else "\n"
        return (text + ending + "\n[boot]\n" + BOOT_LINE).encode("utf-8")
    first = boots[0] + 1
    last = next((i for _, i in sections if i >= first), len(lines))
    commands = []
    for index in range(first, last):
        line = lines[index].strip()
        if not line or line.startswith(("#", ";")):
            continue
        match = re.match(r"^([^=:]+)\s*[:=](.*)$", line)
        if match and match.group(1).strip().lower() == "command":
            commands.append((index, match.group(2).strip()))
    if len(commands) > 1 or (commands and commands[0][1] != BOOT_COMMAND):
        raise RuntimeError("WSL_BOOT_OWNER_CONFLICT")
    if commands:
        return original
    if last and not lines[last - 1].endswith("\n"):
        lines[last - 1] += "\n"
    lines.insert(last, BOOT_LINE)
    return "".join(lines).encode("utf-8")


def boot_hook_status():
    try:
        if not safe_existing(WSL_CONF):
            return "MISSING"
        updated = merge_boot_setting(WSL_CONF.read_bytes())
        if updated != WSL_CONF.read_bytes():
            return "MISSING"
        if not safe_existing(BOOT_SCRIPT, '"""INTERNET owned'):
            return "MISSING"
        if not safe_existing(GUEST_SCRIPT, '"""INTERNET WSL'):
            return "MISSING"
        return "INSTALLED"
    except (OSError, ValueError, RuntimeError):
        return "CONFLICT"


def read_desired():
    if not safe_existing(STATE):
        return {"schema": 1, "desired": "OFF"}
    if STATE.stat().st_size > 256:
        raise RuntimeError("WSL_BOOT_DESIRED_INVALID")
    try:
        value = json.loads(STATE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise RuntimeError("WSL_BOOT_DESIRED_INVALID") from None
    if (not isinstance(value, dict)
            or value.get("schema") != 1 or value.get("desired") not in ("OFF", "ON")):
        raise RuntimeError("WSL_BOOT_DESIRED_INVALID")
    if value["desired"] == "ON" and not valid_public(value.get("windows_public", "")):
        raise RuntimeError("WSL_BOOT_DESIRED_INVALID")
    return value


def valid_public(key):
    return (isinstance(key, str) and len(key) == 44 and key.endswith("=")
            and bool(re.fullmatch(r"[A-Za-z0-9+/]{43}=", key)))


def install():
    check_root()
    if not safe_existing(WSL_CONF):
        raise RuntimeError("WSL_BOOT_CONF_MISSING")
    old_conf = WSL_CONF.read_bytes()
    next_conf = merge_boot_setting(old_conf)  # Reject another owner's command before any write.
    if safe_existing(BOOT_SCRIPT, '"""INTERNET owned'):
        pass
    if safe_existing(GUEST_SCRIPT, '"""INTERNET WSL'):
        pass
    data = sys.stdin.buffer.read(90000)
    if not data:
        raise RuntimeError("WSL_BOOT_INSTALL_SOURCE_MISSING")
    try:
        sources = json.loads(data)
        boot = sources["boot"].encode("utf-8")
        guest = sources["guest"].encode("utf-8")
    except (KeyError, ValueError, TypeError):
        raise RuntimeError("WSL_BOOT_INSTALL_SOURCE_INVALID") from None
    if (len(boot) > 55000 or len(guest) > 30000
            or not boot.startswith(b'"""INTERNET owned')
            or not guest.startswith(b'"""INTERNET WSL')):
        raise RuntimeError("WSL_BOOT_INSTALL_SOURCE_INVALID")
    put_owned(BOOT_SCRIPT, boot, 0o700)
    put_owned(GUEST_SCRIPT, guest, 0o700)
    if next_conf != old_conf:
        mode = WSL_CONF.stat().st_mode & 0o777
        put_owned(WSL_CONF, next_conf, mode)
    if boot_hook_status() != "INSTALLED":
        raise RuntimeError("WSL_BOOT_INSTALL_READBACK_FAILED")
    print(json.dumps({"ok": True, "boot_hook": "INSTALLED", "changed": next_conf != old_conf}))


def set_desired(turn_on, key=None):
    check_root()
    if turn_on and (boot_hook_status() != "INSTALLED" or not valid_public(key)):
        raise RuntimeError("WSL_BOOT_HOOK_NOT_READY")
    if not turn_on and not STATE.exists():
        print(json.dumps({"ok": True, "desired": "OFF", "changed": False}))
        return
    try:
        before = read_desired()
    except RuntimeError:
        if turn_on:
            raise
        # Explicit OFF may clear corrupt but still root-owned saved desire.
        # A corrupt file must never authorize boot activation.
        safe_existing(STATE)
        before = {"schema": 1, "desired": "UNKNOWN"}
    after = {"schema": 1, "desired": "ON", "windows_public": key} if turn_on else {
        "schema": 1, "desired": "OFF"}
    changed = before != after
    if changed:
        put_owned(STATE, (json.dumps(after, separators=(",", ":")) + "\n").encode(), 0o600)
    print(json.dumps({"ok": True, "desired": after["desired"], "changed": changed}))


def restoration_running():
    if not LOCK.exists():
        return False
    with locked_file() as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(stream, fcntl.LOCK_UN)
            return False
        except BlockingIOError:
            return True


def locked_file():
    """Reject an unowned/symlink lock before privileged boot reconciliation."""
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(LOCK, flags, 0o600)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or (info.st_mode & 0o077):
        os.close(fd)
        raise RuntimeError("WSL_BOOT_LOCK_UNOWNED")
    return os.fdopen(fd, "a+b")


def status():
    check_root()
    desired = read_desired()["desired"]
    last = None
    if RESULT.exists() and RESULT.stat().st_size <= 512:
        try:
            last = json.loads(RESULT.read_text())
        except (OSError, ValueError):
            last = None
    print(json.dumps({"ok": True, "desired": desired, "boot_hook": boot_hook_status(),
                      "restore_in_progress": restoration_running(),
                      "last_boot_restore": last}))


def record(reason, state):
    result = {"reason_code": reason, "state": state, "time": int(time.time())}
    put_owned(RESULT, json.dumps(result, separators=(",", ":")).encode(), 0o600)


def load_guest():
    spec = importlib.util.spec_from_file_location("internet_wsl_tun_guest", GUEST_SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("WSL_BOOT_GUEST_SOURCE_MISSING")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def windows_expectations(guest, guest_public):
    """Inspect native config only; never launch or reconfigure Windows sing-box."""
    if WINDOWS_CONFIG.is_symlink() or not WINDOWS_CONFIG.is_file():
        raise RuntimeError("WSL_BOOT_WINDOWS_CONFIG_UNAVAILABLE")
    if WINDOWS_CONFIG.stat().st_size > 3_000_000:
        raise RuntimeError("WSL_BOOT_WINDOWS_CONFIG_INVALID")
    try:
        native = json.loads(WINDOWS_CONFIG.read_text())
        endpoint = native["endpoints"][0]
        peer = endpoint["peers"][0]
        selected = next(x for x in native["outbounds"] if x["tag"] == "wsl-selector")
        chosen = selected["default"]
        vm = next(x for x in native["outbounds"] if x["tag"] == "direct-vless")["server"]
        guest_address = guest.route_state()["guest_ipv4"]
        owned_rules = [rule for rule in native["route"]["rules"]
                       if rule.get("inbound") == ["wsl-kernel"]]
        if (endpoint["tag"] != "wsl-kernel" or endpoint["type"] != "wireguard"
                or endpoint["address"] != ["10.222.28.1/30"]
                or endpoint["listen_port"] != 43913 or endpoint.get("detour") is not None
                or len(endpoint["peers"]) != 1 or len(owned_rules) != 1
                or owned_rules[0].get("outbound") != "wsl-selector"
                or peer["port"] != 43912
                or peer["allowed_ips"] != ["10.222.28.2/32"]
                or peer["persistent_keepalive_interval"] != 2
                or peer["address"] != guest_address or peer["public_key"] != guest_public
                or chosen not in ("direct-auto", "direct-hysteria2", "direct-vless",
                                  "warp-auto", "warp-hysteria2", "warp-vless")):
            raise ValueError("mismatched endpoint")
        vm_address = ipaddress.IPv4Address(vm)
        if not vm_address.is_global:
            raise ValueError("invalid endpoint")
        return chosen.startswith("direct-"), str(vm_address)
    except (OSError, KeyError, IndexError, TypeError, ValueError, StopIteration):
        raise RuntimeError("WSL_BOOT_WINDOWS_CONFIG_MISMATCH") from None


def current_desired_on():
    return read_desired()["desired"] == "ON"


def check_https(expect_vm, vm):
    env = {key: value for key, value in os.environ.items() if key.lower() not in
           ("http_proxy", "https_proxy", "all_proxy")}
    result = subprocess.run(
        ["/usr/bin/curl", "-4", "--noproxy", "*", "-fsS", "--retry", "0",
         "--max-time", "15", "https://api.ipify.org"],
        env=env, capture_output=True, text=True, timeout=18)
    if result.returncode != 0:
        raise RuntimeError("WSL_BOOT_HTTPS_UNREACHABLE")
    try:
        ip = ipaddress.IPv4Address(result.stdout.strip())
    except ipaddress.AddressValueError:
        raise RuntimeError("WSL_BOOT_HTTPS_IP_INVALID") from None
    if not ip.is_global or (expect_vm and str(ip) != vm):
        raise RuntimeError("WSL_BOOT_HTTPS_VM_MISMATCH")


def restore():
    check_root()
    LOCK.parent.mkdir(parents=True, exist_ok=True)
    with locked_file() as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        prepared = False
        guest = None
        guest_public = None
        try:
            if not current_desired_on():
                record("WSL_BOOT_DESIRED_OFF", "OFF")
                return
            if boot_hook_status() != "INSTALLED":
                raise RuntimeError("WSL_BOOT_OWNER_CONFLICT")
            guest = load_guest()
            state = guest.route_state()
            # Ubuntu's systemd resolver and DrvFs may appear slightly after
            # the WSL [boot] command returns. Bound startup readiness without
            # changing Windows or the guest default route.
            until_ready = time.monotonic() + 12
            while not (guest.dns_ready() and WINDOWS_CONFIG.is_file()):
                if not current_desired_on():
                    raise RuntimeError("WSL_BOOT_CANCELLED_BY_OFF")
                if time.monotonic() >= until_ready:
                    raise RuntimeError("WSL_BOOT_PREREQUISITES_UNAVAILABLE")
                time.sleep(0.4)
            guest_public = guest.sudo(
                "/usr/bin/sh", "-c",
                "/usr/bin/wg pubkey < /etc/wireguard/internet-wsl.key").stdout.strip()
            if not valid_public(guest_public):
                raise RuntimeError("WSL_BOOT_GUEST_KEY_INVALID")
            expect_vm, vm = windows_expectations(guest, guest_public)
            if not current_desired_on():
                raise RuntimeError("WSL_BOOT_CANCELLED_BY_OFF")
            if (state["kernel_interface"] and state["route_active"] and
                    state["dns_redirected"] and state["ipv6_guard"] and
                    state["handshake_observed"]):
                check_https(expect_vm, vm)
                if not current_desired_on():
                    raise RuntimeError("WSL_BOOT_CANCELLED_BY_OFF")
                record("WSL_BOOT_ALREADY_ACTIVE_HTTPS_CONFIRMED", "ON")
                return
            if (state["kernel_interface"] or state["owned_route_rules"] or
                    state["dns_redirected"] or state["ipv6_guard"] or
                    state["unexpected_route"]):
                raise RuntimeError("WSL_BOOT_GUEST_NOT_CLEAN")
            guest.prepare(read_desired()["windows_public"])
            prepared = True
            guest.run("/usr/bin/ping", "-n", "-c", "1", "-W", "1",
                      "-I", guest.IFACE, "10.222.28.1", check=False)
            until = time.monotonic() + 25
            while time.monotonic() < until:
                if not current_desired_on():
                    raise RuntimeError("WSL_BOOT_CANCELLED_BY_OFF")
                if guest.route_state()["handshake_observed"]:
                    break
                time.sleep(0.4)
            else:
                raise RuntimeError("WSL_BOOT_HANDSHAKE_UNVERIFIED")
            if not current_desired_on():
                raise RuntimeError("WSL_BOOT_CANCELLED_BY_OFF")
            guest.activate(guest_public)
            check_https(expect_vm, vm)
            state = guest.route_state()
            if not (state["kernel_interface"] and state["route_active"]
                    and state["dns_redirected"] and state["ipv6_guard"]
                    and state["handshake_observed"]):
                raise RuntimeError("WSL_BOOT_READBACK_UNVERIFIED")
            if not current_desired_on():
                raise RuntimeError("WSL_BOOT_CANCELLED_BY_OFF")
            record("WSL_BOOT_IPV4_HTTPS_CONFIRMED", "ON")
        except Exception as error:
            code = str(error) if isinstance(error, RuntimeError) else "WSL_BOOT_IO_FAILED"
            if prepared:
                try:
                    guest.deactivate(guest_public)
                except Exception:
                    code = "WSL_BOOT_ROLLBACK_UNCONFIRMED"
            record(code, "OFF" if code != "WSL_BOOT_ROLLBACK_UNCONFIRMED" else "UNKNOWN")


def spawn():
    check_root()
    if not current_desired_on():
        return
    subprocess.Popen(
        ["/usr/bin/python3", str(BOOT_SCRIPT), "restore"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True, close_fds=True)


def main():
    if len(sys.argv) < 2:
        raise RuntimeError("WSL_BOOT_ACTION_REQUIRED")
    action = sys.argv[1]
    if action == "install" and len(sys.argv) == 2:
        install()
    elif action == "set-on" and len(sys.argv) == 3:
        set_desired(True, sys.argv[2])
    elif action == "set-off" and len(sys.argv) == 2:
        set_desired(False)
    elif action == "status" and len(sys.argv) == 2:
        status()
    elif action == "spawn" and len(sys.argv) == 2:
        spawn()
    elif action == "restore" and len(sys.argv) == 2:
        restore()
    else:
        raise RuntimeError("WSL_BOOT_ACTION_INVALID")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError) as error:
        code = str(error) if isinstance(error, RuntimeError) else "WSL_BOOT_IO_FAILED"
        print(json.dumps({"ok": False, "reason_code": code}))
        sys.exit(4)
