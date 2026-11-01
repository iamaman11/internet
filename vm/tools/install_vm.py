#!/usr/bin/env python3
"""One-shot S1 provisioning over pinned SSH. No agent, service or secret bridge.

Run only as a trusted child of nested Local Secret Vault run-file commands.
All secret values stay in memory during transport; the VM keeps its required
sing-box runtime configuration files. Never log SSH input or configuration.
"""
import argparse
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
ORIGIN = "https://github.com/iamaman11/internet.git"
VALID_ORIGINS = {ORIGIN, "https://github.com/iamaman11/internet", "git@github.com:iamaman11/internet.git"}


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


def sync_source(local_sha):
    """Fast-forward the existing VM checkout; never reset or discard local work."""
    reported = ssh("hostname; sudo -n id -u; git -C " + VM_SOURCE + " rev-parse HEAD").splitlines()
    if len(reported) != 3 or reported[:2] != [VM_HOSTNAME, "0"]:
        raise RuntimeError("VM_IDENTITY_MISMATCH")
    if ssh("git -C " + VM_SOURCE + " remote get-url origin") not in VALID_ORIGINS:
        raise RuntimeError("VM_REPOSITORY_MISMATCH")
    if ssh("git -C " + VM_SOURCE + " status --porcelain --untracked-files=no"):
        raise RuntimeError("VM_SOURCE_DIRTY")
    if reported[2] == local_sha:
        return
    ssh("git -C " + VM_SOURCE + " fetch --quiet origin main")
    if ssh("git -C " + VM_SOURCE + " rev-parse FETCH_HEAD") != local_sha:
        raise RuntimeError("VM_FETCH_HEAD_MISMATCH")
    ssh("git -C " + VM_SOURCE + " merge --ff-only FETCH_HEAD")
    if ssh("git -C " + VM_SOURCE + " rev-parse HEAD") != local_sha:
        raise RuntimeError("VM_SOURCE_UPDATE_UNVERIFIED")


def archive(files, *, only="all"):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as tar:
        directory = tarfile.TarInfo("runtime")
        directory.type = tarfile.DIRTYPE
        directory.mode = 0o700
        tar.addfile(directory)
        for name in (("line2.json",) if only == "line2" else ("line1.json", "line2.json")):
            encoded = files[name].encode("utf-8")
            meta = tarfile.TarInfo("runtime/" + name)
            meta.size = len(encoded)
            meta.mode = 0o600
            tar.addfile(meta, io.BytesIO(encoded))
    return stream.getvalue()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", choices=("all", "line2"), default="all")
    args = parser.parse_args()
    if not all(os.environ.get(x) for x in ("INTERNET_VM_AUTH_FILE", "INTERNET_SSH_KEY")):
        raise ValueError("VAULT_BINDING_MISSING")
    source = str(Path(__file__).resolve().parents[2])
    def local_git(*args):
        return subprocess.run(["git", "-C", source, *args], check=True,
                              capture_output=True, text=True).stdout.strip()
    if local_git("remote", "get-url", "origin") not in VALID_ORIGINS:
        raise RuntimeError("LOCAL_REPOSITORY_MISMATCH")
    if local_git("status", "--porcelain", "--untracked-files=no"):
        raise RuntimeError("LOCAL_SOURCE_DIRTY")
    local_source = local_git("rev-parse", "HEAD")
    sync_source(local_source)
    payload = json.loads(Path(os.environ["INTERNET_VM_AUTH_FILE"]).read_text(encoding="utf-8"))
    files = prepare(payload, "miu.alegria.by", "www.cloudflare.com")
    ssh("sudo -n install -d -m 755 /opt/internet " + VM_ROOT +
        " && sudo -n cp -a " + VM_SOURCE + "/vm/. " + VM_ROOT + "/"
        " && sudo -n install -d -m 700 " + VM_ROOT + "/runtime")
    ssh("sudo -n tar -xf - -C " + VM_ROOT, data=archive(files, only=args.only))
    receipt = ssh("sudo -n stat -c %a " + VM_ROOT + "/runtime/line1.json " +
                  VM_ROOT + "/runtime/line2.json; "
                  "sudo -n docker compose --env-file " + VM_ROOT + "/images.env.example "
                  "-f " + VM_ROOT + "/compose.yaml config --quiet && echo COMPOSE_VALID")
    if receipt.splitlines() != ["600", "600", "COMPOSE_VALID"]:
        raise RuntimeError("INSTALL_READBACK_UNEXPECTED")
    print("VM_IDENTITY=PASS")
    print("VM_SOURCE_SHA=" + local_source)
    print("CONFIG_INSTALL=PASS")
    print("CONFIG_MODE=0600")
    print("DOCKER_COMPOSE_CONFIG=PASS")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
        print("S1_INSTALL_FAILED")
        raise SystemExit(1) from None
