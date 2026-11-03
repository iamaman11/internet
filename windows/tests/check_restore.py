#!/usr/bin/env python3
"""Disposable CI: native configure, complete settings backup, safe restore/negatives."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "windows"), str(ROOT / "vm" / "tools")]
from configure_from_vault import build
from generate_auth import generate

CLI = Path("C:/internet/internet.exe")
NATIVE = Path("C:/internet/sing-box.exe")
CONFIG = Path("C:/internet/config/sing-box.json")
TUN = Path("C:/internet/config/tun.json")

def check(value, code):
    if not value:
        raise AssertionError(code)

def cmd(*args, data=None, fail=None):
    r = subprocess.run([str(CLI), *args, "--json"], input=data,
                       capture_output=True, timeout=35)
    try:
        result = json.loads(r.stdout)
    except (UnicodeError, ValueError):
        raise AssertionError("CLI_JSON_FAILED") from None
    if fail is None:
        check(r.returncode == 0 and result.get("ok") is True, "CLI_SUCCESS_EXPECTED")
    else:
        check(r.returncode != 0 and result.get("reason_code") == fail,
              "CLI_NEGATIVE_EXPECTED")
    return result

def config():
    return json.loads(CONFIG.read_text(encoding="utf-8"))

def state():
    return json.loads(TUN.read_text(encoding="utf-8"))

def routes():
    out = {x["tag"]: x for x in config()["outbounds"]}
    return out["desktop-selector"]["default"], out["wsl-selector"]["default"]

def hashes():
    return tuple(hashlib.sha256(p.read_bytes()).hexdigest() for p in (CONFIG,TUN))

def native_check():
    check(len(config()["inbounds"]) == 2 and not state()["managed_tun"],
          "TUN_ACTIVATED")
    r = subprocess.run([str(NATIVE), "check", "-c", str(CONFIG)],
                       capture_output=True, timeout=25)
    check(r.returncode == 0, "NATIVE_CHECK_FAILED")

def backup(folder, value):
    folder.mkdir()
    (folder / "internet-settings.json").write_text(json.dumps(value), encoding="utf-8")

def main():
    check(CLI.is_file() and NATIVE.is_file() and not CONFIG.exists(),
          "NOT_CLEAN_INSTALL")
    # Fixture secrets never leave the disposable CI host.
    native = build(generate(), "8.8.8.8")
    cmd("configure", "--stdin", data=json.dumps(native).encode())
    check(routes() == ("direct-auto", "direct-auto"), "DEFAULT_ROUTES_INVALID")
    cmd("route", "warp-vless")
    cmd("wsl", "route", "direct-hysteria2")
    cmd("selected-apps", "add", "codex.exe")
    cmd("selected-apps", "on")
    native_check()
    with tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"],
                                     prefix="internet-restore-") as temp:
        root = Path(temp)
        good = root / "good"
        cmd("backup", "export", str(good))
        original = json.loads((good / "internet-settings.json").read_text())
        check(original["schema"] == "internet-settings-v2"
              and original["contains_secrets"] is False
              and original["desktop"] == "warp-vless"
              and original["wsl"] == "direct-hysteria2"
              and original["tun"]["applications"] == ["codex.exe"]
              and original["tun"]["selected_apps"] is True, "BACKUP_INCOMPLETE")
        print("U2_COMPLETE_SETTINGS_EXPORT=PASS", flush=True)

        cmd("route", "direct-vless")
        cmd("wsl", "route", "warp-auto")
        cmd("selected-apps", "add", "firefox.exe")
        before = hashes()
        invalids = [
            ("bad-json", b"{not json", "BACKUP_JSON_INVALID"),
            ("bad-schema", {**original, "schema": "internet-selectors-v1"}, "BACKUP_SCHEMA_INVALID"),
            ("extra-field", {**original, "foreign": True}, "BACKUP_FIELDS_INVALID"),
            ("invalid-app-path", {**original, "tun": {**original["tun"],
               "applications": ["..\\sing-box.exe"]}}, "BACKUP_TUN_INVALID")
        ]
        for name, value, reason in invalids:
            path = root / name
            if isinstance(value, bytes):
                path.mkdir()
                (path / "internet-settings.json").write_bytes(value)
            else:
                backup(path, value)
            cmd("restore", str(path), fail=reason)
            check(before == hashes(), "INVALID_BACKUP_MUTATED_STATE")
        print("U2_INVALID_BACKUPS_NOOP=PASS", flush=True)

        result = cmd("restore", str(good))
        check(result["managed_tun_restored"] is False
              and routes() == ("warp-vless", "direct-hysteria2")
              and state()["selected_apps"] is True
              and state()["applications"] == ["codex.exe"], "RESTORE_STATE_MISMATCH")
        native_check()
        print("U2_STOPPED_RESTORE=PASS", flush=True)
        before = hashes()
        cmd("restore", str(good))
        check(before == hashes(), "REPEAT_RESTORE_NOT_IDEMPOTENT")
        print("U2_REPEATED_RESTORE_NOOP=PASS", flush=True)

        on = copy.deepcopy(original)
        on["tun"]["managed_tun"] = True
        saved_on = root / "saved-on"
        backup(saved_on, on)
        result = cmd("restore", str(saved_on))
        check(result["managed_tun_saved"] is True
              and result["managed_tun_restored"] is False
              and state()["applications"] == ["codex.exe"],
              "RESTORE_ACTIVATED_TUN_OR_LOST_APPS")
        native_check()
        print("U2_TUN_RESTORED_INACTIVE=PASS", flush=True)
    print("U2_NO_PRODUCTION_NETWORK_OR_SECRETS=PASS", flush=True)

if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, ValueError, KeyError, TypeError,
            subprocess.TimeoutExpired) as e:
        print("U2_RESTORE_CI=FAILED " +
              (str(e) if isinstance(e, AssertionError) else type(e).__name__),
              flush=True)
        sys.exit(1)

