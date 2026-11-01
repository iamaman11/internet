#!/usr/bin/env python3
"""One-shot S1 provisioning over pinned SSH. No agent, service or secret bridge.

Run only as a trusted child of nested Local Secret Vault run-file commands.
All secret values stay in memory during transport; the VM keeps its required
sing-box runtime configuration files. Never log SSH input or configuration.
"""
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile

from render_runtime import prepare

HOST = "64.176.74.102"
VM_HOSTNAME = "internet-waw-1gb-20261101-151755-4af5b6"
VM_SOURCE = "/tmp/internet-s1-src"
VM_ROOT = "/opt/internet/vm"
HOST_KEYS = "/mnt/c/Users/Bose/.ssh/known_hosts_internet_1gb_v1"


def ssh(command, *, data=None):
    key = os.environ["INTERNET_SSH_KEY"]
    proc = subprocess.run(
        ["ssh", "-i", key, "-o", "BatchMode=yes",
         "-o", "StrictHostKeyChecking=yes",
         "-o", "UserKnownHostsFile=" + HOST_KEYS,
         "internet@" + HOST, command],
        input=data, capture_output=True,
        timeout=45,
    )
    if proc.returncode:
        raise RuntimeError("REMOTE_OPERATION_FAILED")
    return proc.stdout.decode("utf-8", errors="replace").strip()


def archive(files):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as tar:
        directory = tarfile.TarInfo("runtime")
        directory.type = tarfile.DIRTYPE
        directory.mode = 0o700
        tar.addfile(directory)
        for name in ("line1.json", "line2.json"):
            encoded = files[name].encode("utf-8")
            meta = tarfile.TarInfo("runtime/" + name)
            meta.size = len(encoded)
            meta.mode = 0o600
            tar.addfile(meta, io.BytesIO(encoded))
    return stream.getvalue()


def main():
    if not all(os.environ.get(x) for x in ("INTERNET_VM_AUTH_FILE", "INTERNET_SSH_KEY")):
        raise ValueError("VAULT_BINDING_MISSING")
    payload = json.loads(Path(os.environ["INTERNET_VM_AUTH_FILE"]).read_text(encoding="utf-8"))
    files = prepare(payload, "miu.alegria.by", "www.cloudflare.com")
    local_source = subprocess.run(["git", "-C", str(Path(__file__).resolve().parents[2]),
                                   "rev-parse", "HEAD"], check=True, capture_output=True,
                                  text=True).stdout.strip()
    reported = ssh("hostname; sudo -n id -u; git -C " + VM_SOURCE + " rev-parse HEAD").splitlines()
    if reported != [VM_HOSTNAME, "0", local_source]:
        raise RuntimeError("VM_IDENTITY_OR_SOURCE_MISMATCH")
    ssh("sudo -n install -d -m 755 /opt/internet " + VM_ROOT +
        " && sudo -n cp -a " + VM_SOURCE + "/vm/. " + VM_ROOT + "/"
        " && sudo -n install -d -m 700 " + VM_ROOT + "/runtime")
    ssh("sudo -n tar -xf - -C " + VM_ROOT, data=archive(files))
    receipt = ssh("sudo -n stat -c %a " + VM_ROOT + "/runtime/line1.json " +
                  VM_ROOT + "/runtime/line2.json; "
                  "sudo -n docker compose --env-file " + VM_ROOT + "/images.env.example "
                  "-f " + VM_ROOT + "/compose.yaml config --quiet && echo COMPOSE_VALID")
    if receipt.splitlines() != ["600", "600", "COMPOSE_VALID"]:
        raise RuntimeError("INSTALL_READBACK_UNEXPECTED")
    print("VM_IDENTITY=PASS")
    print("CONFIG_INSTALL=PASS")
    print("CONFIG_MODE=0600")
    print("DOCKER_COMPOSE_CONFIG=PASS")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
        print("S1_INSTALL_FAILED")
        raise SystemExit(1) from None
