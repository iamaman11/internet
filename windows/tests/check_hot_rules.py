#!/usr/bin/env python3
"""Disposable Windows CI: prove native sing-box 1.14.2 local rule-set hot reload.

No TUN, VM, credentials, production paths, firewall changes, or external network.
"""
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

NATIVE = Path("C:/internet/sing-box.exe")

def check(value, code):
    if not value:
        raise AssertionError(code)

def recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        data = conn.recv(n - len(buf))
        if not data:
            raise OSError("SOCKS_EOF")
        buf += data
    return buf

def local_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]

def route_through_socks(proxy, target):
    try:
        with socket.create_connection(("127.0.0.1", proxy), timeout=1) as conn:
            conn.settimeout(2)
            conn.sendall(b"\x05\x01\x00")
            if recv_exact(conn, 2) != b"\x05\x00":
                return False
            conn.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1")
                         + struct.pack("!H", target))
            header = recv_exact(conn, 4)
            if header[:2] != b"\x05\x00":
                return False
            typ = header[3]
            if typ == 1: recv_exact(conn, 4)
            elif typ == 4: recv_exact(conn, 16)
            else: return False
            recv_exact(conn, 2)
            conn.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            return b"HTTP/1.0 200" in conn.recv(200)
    except (OSError, TimeoutError):
        return False

def write_atomic(path, data):
    stage = path.with_suffix(".incoming.json")
    with stage.open("x", encoding="utf-8") as f:
        json.dump(data, f, separators=(",", ":"))
        f.flush()
        os.fsync(f.fileno())
    os.replace(stage, path)

def native_check(path, expect=True):
    r = subprocess.run([str(NATIVE), "check", "-c", str(path)],
                       capture_output=True, timeout=15)
    check((r.returncode == 0) == expect,
          "HOT_RULESET_NATIVE_CHECK_WRONG_VERDICT")

def serve_test_http(sock, shutdown):
    sock.settimeout(0.3)
    while not shutdown.is_set():
        try:
            client, _ = sock.accept()
        except socket.timeout:
            continue
        except OSError:
            return
        with client:
            client.settimeout(1)
            try:
                client.recv(1024)
                client.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            except OSError:
                pass

def main():
    check(NATIVE.is_file(), "SING_BOX_MISSING")
    with tempfile.TemporaryDirectory(prefix="internet-u3-hot-", dir=os.environ["RUNNER_TEMP"]) as tmp:
        root = Path(tmp)
        rules = root / "apps.json"
        config_file = root / "config.json"
        target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target.bind(("127.0.0.1", 0))
        target.listen()
        target_port = target.getsockname()[1]
        proxy_port = local_port()
        done = threading.Event()
        thread = threading.Thread(target=serve_test_http, args=(target, done), daemon=True)
        thread.start()
        try:
            initial = {"version":3, "rules":[{"port":[target_port]}]}
            write_atomic(rules, initial)
            config = {
                "log":{"level":"error"},
                "inbounds":[{"type":"mixed","listen":"127.0.0.1",
                             "listen_port":proxy_port,"tag":"local"}],
                "outbounds":[{"type":"direct","tag":"direct"}],
                "route":{"rule_set":[{"type":"local","tag":"dynamic",
                                      "format":"source","path":str(rules)}],
                         "rules":[{"rule_set":["dynamic"],"action":"reject"}],
                         "final":"direct"}
            }
            config_file.write_text(json.dumps(config), encoding="utf-8")
            native_check(config_file)
            proc = subprocess.Popen([str(NATIVE), "run", "-c", str(config_file)],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                # Initial block: a running SOCKS proxy is reachable, but the
                # destination port must be denied by the local rule-set.
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if proc.poll() is not None:
                        raise AssertionError("SING_BOX_EXITED_EARLY")
                    try:
                        with socket.create_connection(("127.0.0.1", proxy_port), timeout=0.3):
                            break
                    except OSError:
                        time.sleep(0.07)
                else:
                    raise AssertionError("SING_BOX_LISTENER_NOT_READY")
                check(not route_through_socks(proxy_port, target_port),
                      "INITIAL_RULE_DID_NOT_REJECT")
                write_atomic(rules, {"version":3,"rules":[]})
                deadline = time.monotonic() + 9
                while time.monotonic() < deadline and not route_through_socks(proxy_port, target_port):
                    check(proc.poll() is None, "SING_BOX_EXITED_ON_HOT_UPDATE")
                    time.sleep(0.18)
                check(route_through_socks(proxy_port, target_port), "HOT_RELOAD_NOT_APPLIED")
                check(proc.poll() is None, "SING_BOX_RESTARTED_UNEXPECTEDLY")
                print("U3_NATIVE_HOT_RELOAD_SAME_PID=PASS",flush=True)
            finally:
                if proc.poll() is None:
                    proc.terminate()
                try:proc.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=4)

            # Native parser must understand exact Windows process path rules.
            write_atomic(rules, {"version":3,"rules":[
                {"process_name":["msedge.exe"]},
                {"process_path":["c:\\program files (x86)\\microsoft\\edge\\application\\msedge.exe"]}]})
            native_check(config_file)
            print("U3_NATIVE_PROCESS_NAME_AND_PATH=PASS",flush=True)
            rules.write_text("{invalid-json", encoding="utf-8")
            native_check(config_file, expect=False)
            print("U3_NATIVE_REJECTS_INVALID_RULESET=PASS",flush=True)
        finally:
            done.set()
            target.close()
            thread.join(timeout=2)
    print("U3_NO_TUN_VM_SECRETS_OR_NETWORK_MUTATION=PASS",flush=True)

if __name__ == "__main__":
    try:main()
    except (OSError,AssertionError,subprocess.TimeoutExpired,KeyError) as e:
        print("U3_NATIVE_HOT_RULES=FAILED "+(str(e) if isinstance(e,AssertionError)
              else type(e).__name__),flush=True)
        sys.exit(1)

