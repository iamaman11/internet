"""S1 structural checks; physical egress and native sing-box check remain mandatory."""
import json
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1] / "templates"

def load(name):
    return json.loads((ROOT / name).read_text(encoding="utf-8"))

def selected_outbound(config, tag):
    # This intentionally models only exact inbound routing and final.
    for rule in config["route"]["rules"]:
        if tag in rule.get("inbound", []):
            return rule["outbound"]
    return config["route"]["final"]

def assert_routing_isolation(config, name):
    tags = {item["tag"] for item in config["inbounds"]}
    warp = ({"vless-reality-warp", "hy2-warp"} if name == "line1.json"
            else {"http-proxy-auth", "socks-proxy-auth", "https-proxy-auth"})
    if not warp <= tags:
        raise ValueError("warp inbounds missing")
    for tag in warp:
        if selected_outbound(config, tag) != "warp-local":
            raise ValueError("warp inbound routed outside warp-local: " + tag)
    for tag in tags - warp:
        if selected_outbound(config, tag) != "direct":
            raise ValueError("direct inbound has unexpected route: " + tag)
    outbounds = {item["tag"]: item for item in config["outbounds"]}
    if outbounds.get("warp-local", {}).get("server") != "warp-egress":
        raise ValueError("warp egress target is missing")

def ensure_http_proxy_alpn(config):
    for inbound in config["inbounds"]:
        if inbound.get("tls", {}).get("enabled"):
            if inbound["tls"].get("alpn") != ["http/1.1"]:
                raise ValueError("HTTPS_PROXY_ALPN_UNSUPPORTED")


def warp_udp_supported(config):
    socks = next(x for x in config["outbounds"] if x["tag"] == "warp-local")
    return socks.get("network") != "tcp"

class TopologyTests(unittest.TestCase):
    def test_line1_ports_and_auth(self):
        c = load("line1.json")
        self.assertEqual([(x["type"], x["listen_port"]) for x in c["inbounds"]],
            [("vless",443), ("hysteria2",8443), ("vless",5443), ("hysteria2",9444)])
        self.assertTrue(all(x["users"] for x in c["inbounds"]))
        self.assertTrue(all(x.get("tls", {}).get("enabled") for x in c["inbounds"]))

    def test_line2_six_authenticated_inbounds_and_tls(self):
        c = load("line2.json")
        self.assertEqual([(x["type"], x["listen_port"]) for x in c["inbounds"]],
            [("http",3128), ("socks",1080), ("http",9443),
             ("http",4128), ("socks",4080), ("http",4443)])
        self.assertTrue(all(x["users"] and "username" in x["users"][0]
                            and "password" in x["users"][0] for x in c["inbounds"]))
        self.assertTrue(all(x.get("tls", {}).get("enabled") for x in c["inbounds"]
                            if x["listen_port"] in (9443,4443)))

    def test_https_proxy_tls_alpn_matches_sing_box_1_14(self):
        c = load("line2.json")
        ensure_http_proxy_alpn(c)
        self.assertEqual([x["listen_port"] for x in c["inbounds"]
                          if x.get("tls", {}).get("enabled")], [9443, 4443])

    def test_negative_h2_alpn_rejected(self):
        c = load("line2.json")
        next(x for x in c["inbounds"] if x["listen_port"] == 9443)["tls"]["alpn"] = [
            "h2", "http/1.1"
        ]
        with self.assertRaisesRegex(ValueError, "HTTPS_PROXY_ALPN_UNSUPPORTED"):
            ensure_http_proxy_alpn(c)

    def test_one_native_acme_owner_shared_with_line2(self):
        one = load("line1.json")
        two = load("line2.json")
        self.assertEqual(len(one["certificate_providers"]), 1)
        provider = one["certificate_providers"][0]
        self.assertEqual(provider["type"], "acme")
        self.assertEqual(provider["domain"], ["${TUNNEL_DOMAIN}"])
        self.assertTrue(provider["disable_tls_alpn_challenge"])
        self.assertEqual([x["tls"]["certificate_provider"] for x in one["inbounds"]
                          if x["type"] == "hysteria2"], ["s1-tls", "s1-tls"])
        for inbound in two["inbounds"]:
            if inbound.get("tls", {}).get("enabled"):
                self.assertIn("/var/lib/sing-box/certificates/", inbound["tls"]["certificate_path"])
                self.assertIn("${TUNNEL_DOMAIN}", inbound["tls"]["certificate_path"])

    def test_warp_inbounds_never_route_direct(self):
        for name in ("line1.json", "line2.json"):
            c = load(name)
            self.assertEqual(c["route"]["final"], "direct")
            tags = [x["tag"] for x in c["inbounds"]]
            warp = [x for x in tags if ("warp" in x if name == "line1.json"
                       else x in ("http-proxy-auth","socks-proxy-auth","https-proxy-auth"))]
            direct = [x for x in tags if x not in warp]
            self.assertTrue(warp)
            assert_routing_isolation(c, name)
            for tag in warp:
                self.assertEqual(selected_outbound(c,tag), "warp-local")
            for tag in direct:
                self.assertEqual(selected_outbound(c,tag), "direct")
            self.assertTrue(any(x["tag"] == "warp-local" and
                x["type"] == "socks" and x["server"] == "warp-egress"
                for x in c["outbounds"]))

    def test_negative_missing_warp_route_is_detectable(self):
        c = load("line2.json")
        c["route"]["rules"] = [r for r in c["route"]["rules"]
            if "inbound" not in r]
        with self.assertRaisesRegex(ValueError, "warp inbound routed outside"):
            assert_routing_isolation(c, "line2.json")

    def test_warp_tcp_udp_capability_contract(self):
        compose = (ROOT.parent / "compose.yaml").read_text(encoding="utf-8")
        self.assertIn('WARP_ENABLE_NAT: "1"', compose)
        self.assertIn('GOST_ARGS: "-L=socks5://:11080"', compose)
        self.assertIn("cloudflare-mesh:", compose)
        self.assertIn('profiles: ["mobile"]', compose)
        for name in ("line1.json", "line2.json"):
            c = load(name)
            socks = next(x for x in c["outbounds"] if x["tag"] == "warp-local")
            self.assertEqual(socks["type"], "socks")
            self.assertEqual(socks["server_port"], 11080)
            # network=tcp used to silently exclude WARP UDP.
            self.assertNotEqual(socks.get("network"), "tcp")

    def test_negative_tcp_only_warp_is_rejected(self):
        c = load("line1.json")
        socks = next(x for x in c["outbounds"] if x["tag"] == "warp-local")
        socks["network"] = "tcp"
        self.assertEqual(socks["network"], "tcp")  # forbidden regression fixture
        self.assertFalse(warp_udp_supported(c))

    def test_no_literal_credentials(self):
        for name in ("line1.json", "line2.json"):
            c = load(name)
            for inbound in c["inbounds"]:
                for user in inbound["users"]:
                    for key in ("username","password","uuid"):
                        if key in user:
                            self.assertTrue(user[key].startswith("${"), (name,key))
                reality = inbound.get("tls",{}).get("reality",{})
                if reality:
                    self.assertTrue(reality["private_key"].startswith("${"))

if __name__ == "__main__":
    unittest.main()
