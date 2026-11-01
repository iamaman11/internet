#!/usr/bin/env python3
"""Narrow static I16 regression check; native nft --check and live probes are separate."""
import pathlib

GUARD = pathlib.Path(__file__).resolve().parents[1] / "warp" / "gost-egress-guard.nft"
WRAPPER = GUARD.with_name("gost-guard-entrypoint.sh")

ALLOWED = [
    'meta skuid 1000 oifname "lo" accept',
    'meta skuid 1000 oifname "CloudflareWARP" accept',
    'meta skuid 1000 oifname "eth0" ct direction reply accept',
    'meta skuid 1000 counter drop',
]


def check_guard(text: str) -> None:
    code = [s.strip() for s in text.splitlines() if s.strip() and not s.lstrip().startswith("#")]
    if "table inet internet_gost_guard {" not in code:
        raise ValueError("GUARD_TABLE_MISSING")
    if "type filter hook output priority -150; policy accept;" not in code:
        raise ValueError("GUARD_OUTPUT_HOOK_MISSING")
    rules = [s for s in code if s.startswith("meta ") or s.startswith("ct ") or s.startswith("oif")]
    if rules != ALLOWED:
        raise ValueError("GOST_GUARD_RULES_MISMATCH")
    # Unlike iptables ACCEPT or an early return, this guard drops every other
    # locally generated packet from GOST, regardless of the WARP ruleset.
    if code.count("meta skuid 1000 counter drop") != 1:
        raise ValueError("GOST_GUARD_DROP_MISSING")


def check_entrypoint(text: str) -> None:
    code = [s.strip() for s in text.splitlines() if s.strip()]
    if not code or code[0] != "#!/bin/sh":
        raise ValueError("GUARD_INTERPRETER_MISMATCH")
    if "set -eu" not in code or 'if [ "$(id -u)" != "1000" ]; then' not in code:
        raise ValueError("GUARD_FAIL_CLOSED_UID_MISSING")
    install = "sudo nft -f /etc/internet/gost-egress-guard.nft"
    readback = "sudo nft list chain inet internet_gost_guard output"
    start = "exec /entrypoint.sh"
    if not all(any(rule in line for line in code) for rule in (install, readback, start)):
        raise ValueError("GUARD_EXECUTION_CHAIN_MISSING")
    if not (next(i for i,s in enumerate(code) if install in s) <
            next(i for i,s in enumerate(code) if readback in s) <
            code.index(start)):
        raise ValueError("GUARD_INSTALLED_AFTER_GOST")


def main():
    check_guard(GUARD.read_text(encoding="utf-8"))
    check_entrypoint(WRAPPER.read_text(encoding="utf-8"))
    print("GOST_GUARD_CONTRACT_PASS")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError) as exc:
        print("GOST_GUARD_CONTRACT_FAILED:" + str(exc))
        raise SystemExit(1)
