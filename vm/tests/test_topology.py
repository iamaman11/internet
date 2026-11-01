"""S1 structural checks; physical egress and native sing-box check remain mandatory."""
import json
import pathlib
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

    def test_warp_inbounds_never_route_direct(self):
        for name in ("line1.json", "line2.json"):
            c = load(name)
            self.assertEqual(c["route"]["final"], "direct")
            tags = [x["tag"] for x in c["inbounds"]]
            warp = [x for x in tags if ("warp" in x if name == "line1.json"
                       else x in ("http-proxy-auth","socks-proxy-auth","https-proxy-auth"))]
            direct = [x for x in tags if x not in warp]
            self.assertTrue(warp)
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
        self.assertNotEqual(selected_outbound(c,"http-proxy-auth"), "warp-local")

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
