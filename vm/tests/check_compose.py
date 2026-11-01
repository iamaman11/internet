#!/usr/bin/env python3
"""Check native Docker Compose's rendered JSON, without network or secrets."""
import json
import re
import sys

REQUIRED = {
    "warp-egress": set(),
    "line1-gateway": {"443/tcp", "8443/udp", "5443/tcp", "9444/udp"},
    "line2-proxy": {"3128/tcp", "1080/tcp", "9443/tcp", "4128/tcp", "4080/tcp", "4443/tcp"},
}


def check(data):
    services = data["services"]
    assert set(services) == set(REQUIRED), f"unexpected services: {set(services) ^ set(REQUIRED)}"
    assert set(data["networks"]) == {"edge"}, "extra unmanaged networks"
    for name, service in services.items():
        image = service["image"]
        assert re.search(r"@sha256:[a-f0-9]{64}$", image), f"{name}: image must be pinned"
        actual = {
            f'{port["published"]}/{port["protocol"]}'
            for port in service.get("ports", [])
        }
        assert actual == REQUIRED[name], f"{name}: expected {REQUIRED[name]}, got {actual}"
    warp = services["warp-egress"]
    assert warp["environment"]["WARP_ENABLE_NAT"] == "1"
    assert warp["environment"]["GOST_ARGS"] == "-L=socks5://:11080"
    assert any(dev.get("source") == "/dev/net/tun" and dev.get("target") == "/dev/net/tun"
               for dev in warp["devices"])
    for name in ("line1-gateway", "line2-proxy"):
        assert "NET_ADMIN" not in services[name].get("cap_add", [])
        assert not any(dev.get("source") == "/dev/net/tun"
                       for dev in services[name].get("devices", []))
    assert not any("mesh" in name for name in services)


if __name__ == "__main__":
    try:
        with open(sys.argv[1], encoding="utf-8") as handle:
            check(json.load(handle))
    except (AssertionError, KeyError, IndexError, ValueError) as exc:
        print(f"COMPOSE_INVARIANT_FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
    print("COMPOSE_INVARIANTS_PASS")
