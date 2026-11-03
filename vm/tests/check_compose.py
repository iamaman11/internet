#!/usr/bin/env python3
"""Check native Docker Compose's rendered JSON, without network or secrets."""
import json
import re
import sys

REQUIRED = {
    "warp-egress": set(),
    "line1-gateway": {"80/tcp", "443/tcp", "8443/udp", "5443/tcp", "9444/udp"},
    "line2-proxy": {"3128/tcp", "1080/tcp", "9443/tcp", "4128/tcp", "4080/tcp", "4443/tcp"},
}


def check(data, mobile=False):
    services = data["services"]
    expected = set(REQUIRED) | ({"cloudflare-mesh"} if mobile else set())
    assert set(services) == expected, f"unexpected services: {set(services) ^ expected}"
    assert set(data["networks"]) == ({"edge", "mesh"} if mobile else {"edge"}), "extra unmanaged networks"
    for name in REQUIRED:
        service = services[name]
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
    assert warp["entrypoint"] == ["/bin/sh", "/etc/internet/gost-guard-entrypoint.sh"], "guard must start first"
    for target in ("/etc/internet/gost-guard-entrypoint.sh", "/etc/internet/gost-egress-guard.nft"):
        assert any(m.get("target") == target and m.get("read_only") is True
                   for m in warp["volumes"]), "missing read-only guard bind mount: " + target
    assert any(dev.get("source") == "/dev/net/tun" and dev.get("target") == "/dev/net/tun"
               for dev in warp["devices"])
    for name in ("line1-gateway", "line2-proxy"):
        assert "NET_ADMIN" not in services[name].get("cap_add", [])
        assert not any(dev.get("source") == "/dev/net/tun"
                       for dev in services[name].get("devices", []))
    l1 = services["line1-gateway"]["volumes"]
    l2 = services["line2-proxy"]["volumes"]
    assert any(v.get("target") == "/var/lib/sing-box" and not v.get("read_only", False) for v in l1)
    assert any(v.get("target") == "/var/lib/sing-box" and v.get("read_only", False) for v in l2)
    if not mobile:
        assert "cloudflare-mesh" not in services, "mobile must be opt-in"
        return
    mesh = services["cloudflare-mesh"]
    assert mesh["profiles"] == ["mobile"], "mesh must never start with normal Compose"
    assert mesh["image"] == (
        "cloudflare/mesh@sha256:1c135f07ddac619562f45da5816b25d3ac7663a491c2a065bd83c005007dec5e"
    ), "mesh upstream image/digest changed unexpectedly"
    assert set(mesh["networks"]) == {"mesh"}, "mesh must not share existing dataplane"
    assert not mesh.get("ports"), "mesh cannot publish VM ports"
    assert not mesh.get("depends_on"), "mesh must not recreate neighboring services"
    assert set(mesh["cap_add"]) == {"NET_ADMIN", "NET_RAW"}, "mesh privilege scope changed"
    assert any(d.get("source") == "/dev/net/tun" and d.get("target") == "/dev/net/tun"
               for d in mesh["devices"]), "mesh TUN missing"
    assert mesh["environment"].get("SRCNAT_ENABLED") == "true", "mesh source NAT disabled"
    assert mesh["environment"].get("MESH_NODE_TOKEN"), "mesh token missing from protected env-file"
    assert any(v.get("target") == "/var/lib/cloudflare-warp"
               and v.get("type") == "volume"
               and v.get("source") == "mesh-state" for v in mesh["volumes"]), "identity not persisted"
    assert "mesh-state" in data["volumes"], "missing persistent identity volume"


if __name__ == "__main__":
    try:
        with open(sys.argv[1], encoding="utf-8") as handle:
            check(json.load(handle), mobile="--mobile" in sys.argv[2:])
    except (AssertionError, KeyError, IndexError, ValueError) as exc:
        print(f"COMPOSE_INVARIANT_FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
    print("COMPOSE_INVARIANTS_PASS")
