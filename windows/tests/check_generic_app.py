#!/usr/bin/env python3
"""Disposable Windows CI: universal app CLI resolves any running EXE safely."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

EXE = Path(r"C:\internet\internet.exe")
TUN = Path(r"C:\internet\config\tun.json")
CONFIG = Path(r"C:\internet\config\sing-box.json")

def run(*args):
    # Expose exactly which disposable step stalls; no credentials are ever
    # passed to this fixture. Keep the bounded CI safety deadline.
    step = "app " + " ".join(args)
    print(f"U3_STEP_START {step}", flush=True)
    started = time.monotonic()
    try:
        p = subprocess.run([str(EXE), "app", *args, "--json"],
                           capture_output=True, timeout=20)
    except subprocess.TimeoutExpired as exc:
        raise AssertionError(f"U3_COMMAND_TIMEOUT {step}") from exc
    try:
        data = json.loads(p.stdout)
    except (ValueError, UnicodeDecodeError):
        raise AssertionError(f"APP_CLI_REPLY_INVALID {step}") from None
    print(f"U3_STEP_END {step} elapsed_ms={int((time.monotonic()-started)*1000)}", flush=True)
    return p.returncode, data

def same(before):
    assert (CONFIG.read_bytes(), TUN.read_bytes()) == before, "APP_MUTATED_NATIVE_WHILE_TUN_OFF"

def main():
    assert EXE.is_file() and TUN.is_file() and CONFIG.is_file(), "U3_NOT_INSTALLED"
    snapshot = (CONFIG.read_bytes(), TUN.read_bytes())
    with tempfile.TemporaryDirectory(prefix="internet-u3-app-", dir=os.environ["RUNNER_TEMP"]) as temp:
        copied = Path(temp) / "u3probe.exe"
        shutil.copyfile(r"C:\Windows\System32\ping.exe", copied)
        proc = subprocess.Popen([str(copied), "-t", "127.0.0.1"],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        try:
            code, v = run("u3probe.exe", "direct")
            assert code == 0 and v["ok"] and not v["changed"], (
                "U3_GENERIC_NAME_RESOLUTION_FAILED", code, v.get("reason_code"))
            assert v["identity_source"] == "RUNNING_PROCESS_EXACT_PATH", "U3_PATH_NOT_RESOLVED"
            assert v["application"].lower() == str(copied).lower(), "U3_PATH_MISMATCH"
            same(snapshot)
            code, v = run(str(copied), "direct")
            assert code == 0 and v["identity_source"] == "EXPLICIT_EXACT_PATH", "U3_EXACT_PATH_FAILED"
            same(snapshot)
            code, v = run("diagnose", "u3probe.exe")
            assert code == 0 and v["desired_route"] == "DIRECT", "U3_DIAGNOSE_INVALID"
            assert v["physical_egress"] == "NOT_TESTED_BY_STATUS", "U3_DIAGNOSE_FABRICATED_EGRESS"
            code, v = run("u3probe.exe", "vm")
            assert code == 0 and v["ok"] and v["scope"] == "SAVED_INACTIVE", "U3_OFFLINE_VM_SAVE_FAILED"
            assert v["application"].lower() == str(copied).lower(), "U3_OFFLINE_IDENTITY_MISMATCH"
            assert CONFIG.read_bytes() == snapshot[0], "U3_OFFLINE_SAVE_MUTATED_SINGBOX"
            saved = json.loads(TUN.read_text(encoding="utf-8"))
            assert not saved["managed_tun"], "U3_HIDDEN_TUN_ENABLE"
            assert str(copied).lower() in saved["applications"], "U3_SAVED_APP_NOT_FOUND"
            code, v = run("list")
            prior = json.loads(snapshot[1].decode("utf-8"))
            assert code == 0 and v["managed_tun"] is False, "U3_OFFLINE_TUN_CHANGED"
            assert v["selected_apps"] == prior["selected_apps"], "U3_OFFLINE_SELECTED_SWITCH_CHANGED"
            code, v = run("u3probe.exe", "direct")
            assert code == 0 and v["ok"], "U3_OFFLINE_REMOVE_FAILED"
            same(snapshot)
            code, v = run("not-running-u3.exe", "direct")
            assert code != 0 and v["reason_code"] == "APP_NOT_RUNNING_USE_FULL_PATH", "U3_UNKNOWN_NAME_ACCEPTED"
            code, v = run("edge", "vm")
            assert code != 0, "U3_EDGE_ALIAS_STILL_ENABLED"
            same(snapshot)
            code, v = run("list")
            assert code == 0 and v["ok"] and v["managed_tun"] is False, "U3_LIST_UNSAFE"
            print("U3_GENERIC_RUNNING_NAME_EXACT_PATH=PASS", flush=True)
            print("U3_TUN_OFF_SAVES_VM_WITHOUT_NETWORK_MUTATION=PASS", flush=True)
            print("U3_APP_DIAGNOSE_TRUTHFUL=PASS", flush=True)
            print("U3_NO_PER_APPLICATION_ALIAS=PASS", flush=True)
        finally:
            proc.terminate()
            try: proc.wait(timeout=4)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=4)
    same(snapshot)
    print("U3_GENERIC_NO_NETWORK_OR_CONFIG_MUTATION=PASS", flush=True)

if __name__ == "__main__":
    try: main()
    except (AssertionError, OSError, subprocess.TimeoutExpired) as err:
        print("U3_GENERIC_APP_CI=FAILED " +
              (str(err) if isinstance(err, AssertionError) else type(err).__name__), flush=True)
        sys.exit(1)

