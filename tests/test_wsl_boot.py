"""Deterministic boot-hook ownership, NAT/HTTPS rollback and OFF tests."""
import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest import mock


SOURCE = pathlib.Path(__file__).resolve().parents[1] / "src" / "wsl_tun_boot.py"
spec = importlib.util.spec_from_file_location("internet_wsl_boot_tests", SOURCE)
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)


class BootConfigTests(unittest.TestCase):
    def test_boot_insert_preserves_systemd_network_interop_and_is_idempotent(self):
        before = (b"[boot]\nsystemd=true\n\n[network]\n"
                  b"generateResolvConf=false\n[interop]\nenabled=true\n")
        updated = boot.merge_boot_setting(before)
        self.assertIn(b"systemd=true\n", updated)
        self.assertIn(b"generateResolvConf=false\n", updated)
        self.assertIn(b"enabled=true\n", updated)
        self.assertEqual(updated.count(boot.BOOT_LINE.encode()), 1)
        self.assertEqual(boot.merge_boot_setting(updated), updated)

    def test_missing_boot_section_added_without_overwriting(self):
        before = b"[network]\ngenerateResolvConf=false\n"
        updated = boot.merge_boot_setting(before)
        self.assertTrue(updated.startswith(before))
        self.assertIn(b"[boot]\n" + boot.BOOT_LINE.encode(), updated)

    def test_foreign_boot_command_and_duplicate_sections_are_rejected(self):
        for before in [
            b"[boot]\nsystemd=true\ncommand=/other/owner\n",
            b"[boot]\ncommand=foreign\n",
            b"[boot]\ncommand: /other/owner\n",
            b"[boot]\n[boot]\n",
            b"[boot]\ncommand=foreign\ncommand=alsoforeign\n",
        ]:
            with self.subTest(before=before):
                with self.assertRaisesRegex(RuntimeError, "WSL_BOOT_OWNER_CONFLICT"):
                    boot.merge_boot_setting(before)

    def test_invalid_encoding_and_oversize_are_rejected(self):
        for content in [b"\xff", b"x" * 8193]:
            with self.assertRaises(RuntimeError):
                boot.merge_boot_setting(content)

    def test_no_trailing_newline_still_produces_valid_command(self):
        before = b"[boot]\nsystemd=true"
        updated = boot.merge_boot_setting(before)
        self.assertIn(b"systemd=true\n" + boot.BOOT_LINE.encode(), updated)

    def test_no_desired_file_means_off_not_on(self):
        with tempfile.TemporaryDirectory() as folder:
            with mock.patch.object(boot, "STATE", pathlib.Path(folder) / "state.json"):
                self.assertEqual(boot.read_desired()["desired"], "OFF")

    def test_public_key_must_have_wireguard_shape(self):
        self.assertTrue(boot.valid_public("A" * 43 + "="))
        for candidate in ["", "A" * 44, "A" * 43 + "/", "A" * 42 + "=="]:
            self.assertFalse(boot.valid_public(candidate))


class WindowsPreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = pathlib.Path(self.temp.name) / "sing-box.json"
        self.config_patch = mock.patch.object(boot, "WINDOWS_CONFIG", self.config)
        self.config_patch.start()
        self.addCleanup(self.config_patch.stop)
        self.key = "B" * 43 + "="
        self.original = {
            "endpoints": [{
                "tag": "wsl-kernel", "type": "wireguard",
                "address": ["10.222.28.1/30"],
                "listen_port": 43913, "private_key": "SECRET_DO_NOT_EXPOSE",
                "peers": [{"address": "172.26.23.199", "public_key": self.key,
                           "port": 43912, "allowed_ips": ["10.222.28.2/32"],
                           "persistent_keepalive_interval": 2}],
            }],
            "route": {"rules": [{"inbound": ["wsl-kernel"], "outbound": "wsl-selector"}]},
            "outbounds": [
                {"tag": "wsl-selector", "default": "direct-auto"},
                {"tag": "direct-vless", "server": "64.176.74.102"},
            ],
        }
        self.guest = mock.Mock()
        self.guest.route_state.return_value = {"guest_ipv4": "172.26.23.199"}

    def save(self):
        self.config.write_text(json.dumps(self.original))

    def test_valid_endpoint_dynamic_direct_target(self):
        self.save()
        self.assertEqual(boot.windows_expectations(self.guest, self.key),
                         (True, "64.176.74.102"))

    def test_warp_route_keeps_actual_ipv4_check_without_vm_equality(self):
        self.original["outbounds"][0]["default"] = "warp-auto"
        self.save()
        self.assertEqual(boot.windows_expectations(self.guest, self.key),
                         (False, "64.176.74.102"))

    def test_stale_nat_peer_public_or_unowned_endpoint_refuses(self):
        cases = [
            lambda: self.original["endpoints"][0]["peers"][0].update(address="172.26.23.200"),
            lambda: self.original["endpoints"][0]["peers"][0].update(public_key="C"*43+"="),
            lambda: self.original["endpoints"][0].update(detour="unowned"),
            lambda: self.original["endpoints"][0].update(listen_port=12345),
        ]
        for change in cases:
            self.original = json.loads(json.dumps({
                "endpoints": [{
                    "tag": "wsl-kernel", "type": "wireguard",
                    "address": ["10.222.28.1/30"],
                    "listen_port": 43913, "private_key": "SECRET_DO_NOT_EXPOSE",
                    "peers": [{"address": "172.26.23.199", "public_key": self.key,
                               "port": 43912, "allowed_ips": ["10.222.28.2/32"],
                               "persistent_keepalive_interval": 2}],
                }],
                "route": {"rules": [{"inbound": ["wsl-kernel"], "outbound": "wsl-selector"}]},
                "outbounds": [
                    {"tag": "wsl-selector", "default": "direct-auto"},
                    {"tag": "direct-vless", "server": "64.176.74.102"},
                ],
            }))
            change()
            self.save()
            with self.assertRaisesRegex(RuntimeError, "WSL_BOOT_WINDOWS_CONFIG_MISMATCH"):
                boot.windows_expectations(self.guest, self.key)

    def test_missing_config_refuses_without_modifying_guest(self):
        with self.assertRaisesRegex(RuntimeError, "WSL_BOOT_WINDOWS_CONFIG_UNAVAILABLE"):
            boot.windows_expectations(self.guest, self.key)
        self.guest.route_state.assert_not_called()

    def test_non_owned_windows_wg_rule_is_rejected(self):
        self.original["route"]["rules"][0]["outbound"] = "unrelated"
        self.save()
        with self.assertRaisesRegex(RuntimeError, "WSL_BOOT_WINDOWS_CONFIG_MISMATCH"):
            boot.windows_expectations(self.guest, self.key)


class RestoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.lock = pathlib.Path(self.temp.name) / "lock"
        self.config = pathlib.Path(self.temp.name) / "sing-box.json"
        self.config.write_text("{}")
        self.config_patcher = mock.patch.object(boot, "WINDOWS_CONFIG", self.config)
        self.config_patcher.start()
        self.addCleanup(self.config_patcher.stop)
        self.lock_patcher = mock.patch.object(boot, "LOCK", self.lock)
        self.lock_patcher.start()
        self.addCleanup(self.lock_patcher.stop)
        # Tests exercise the transaction with a normal user-owned temporary
        # file; production locked_file enforces root:root 0600 separately.
        self.lock_open_patcher = mock.patch.object(
            boot, "locked_file", side_effect=lambda: self.lock.open("a+b"))
        self.lock_open_patcher.start()
        self.addCleanup(self.lock_open_patcher.stop)
        self.records = []
        self.patchers = [
            mock.patch.object(boot, "check_root"),
            mock.patch.object(boot, "boot_hook_status", return_value="INSTALLED"),
            mock.patch.object(boot, "read_desired", return_value={
                "schema": 1, "desired": "ON", "windows_public": "A"*43+"="}),
            mock.patch.object(boot, "record", side_effect=lambda reason, state:
                              self.records.append((reason, state))),
            mock.patch.object(boot, "windows_expectations",
                              return_value=(True, "64.176.74.102")),
            mock.patch.object(boot, "check_https"),
        ]
        for patcher in self.patchers:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.guest = mock.Mock()
        self.guest.IFACE = "internet-wsl"
        self.guest.route_state.return_value = {
            "kernel_interface": False, "owned_route_rules": False,
            "dns_redirected": False, "ipv6_guard": False,
            "unexpected_route": False, "handshake_observed": True,
            "route_active": True,
        }
        self.guest.dns_ready.return_value = True
        self.guest.sudo.return_value.stdout.strip.return_value = "B"*43+"="
        self.patcher_guest = mock.patch.object(boot, "load_guest", return_value=self.guest)
        self.patcher_guest.start()
        self.addCleanup(self.patcher_guest.stop)

    def test_clean_boot_calls_existing_guest_adapter_and_checks_https(self):
        def states():
            self.guest.route_state.return_value = {
                "kernel_interface": False, "owned_route_rules": False,
                "dns_redirected": False, "ipv6_guard": False,
                "unexpected_route": False, "handshake_observed": True,
                "route_active": True}
        states()
        # The first status must be clean; final status reflects guest activation.
        final = dict(self.guest.route_state.return_value, kernel_interface=True,
                     dns_redirected=True, ipv6_guard=True)
        self.guest.route_state.side_effect = [
            self.guest.route_state.return_value,
            final,
            final,
        ]
        boot.restore()
        self.guest.prepare.assert_called_once()
        self.guest.activate.assert_called_once()
        self.guest.deactivate.assert_not_called()
        self.assertEqual(self.records, [("WSL_BOOT_IPV4_HTTPS_CONFIRMED", "ON")])

    def test_repeated_boot_handoff_does_not_recreate_live_wireguard(self):
        self.guest.route_state.return_value = dict(
            self.guest.route_state.return_value,
            kernel_interface=True, route_active=True, dns_redirected=True,
            ipv6_guard=True, handshake_observed=True)
        boot.restore()
        self.guest.prepare.assert_not_called()
        self.guest.activate.assert_not_called()
        self.assertEqual(self.records, [("WSL_BOOT_ALREADY_ACTIVE_HTTPS_CONFIRMED", "ON")])

    def test_failed_https_rolls_back_guest_and_reports_off(self):
        final = dict(self.guest.route_state.return_value, kernel_interface=True)
        self.guest.route_state.side_effect = [
            self.guest.route_state.return_value, final,
        ]
        with mock.patch.object(boot, "check_https",
                               side_effect=RuntimeError("WSL_BOOT_HTTPS_VM_MISMATCH")):
            boot.restore()
        self.guest.prepare.assert_called_once()
        self.guest.deactivate.assert_called_once()
        self.assertEqual(self.records, [("WSL_BOOT_HTTPS_VM_MISMATCH", "OFF")])

    def test_explicit_off_means_no_guest_mutation(self):
        with mock.patch.object(boot, "read_desired",
                               return_value={"schema": 1, "desired": "OFF"}):
            boot.restore()
        self.guest.prepare.assert_not_called()
        self.guest.activate.assert_not_called()
        self.assertEqual(self.records, [("WSL_BOOT_DESIRED_OFF", "OFF")])

    def test_missing_windows_prerequisite_does_not_change_nat(self):
        with mock.patch.object(boot, "windows_expectations",
                               side_effect=RuntimeError("WSL_BOOT_WINDOWS_CONFIG_MISMATCH")):
            boot.restore()
        self.guest.prepare.assert_not_called()
        self.guest.activate.assert_not_called()
        self.assertEqual(self.records, [("WSL_BOOT_WINDOWS_CONFIG_MISMATCH", "OFF")])

    def test_explicit_off_during_handshake_cancels_and_rolls_back(self):
        desired = iter([True, True, False])
        with mock.patch.object(boot, "current_desired_on",
                               side_effect=lambda: next(desired)):
            boot.restore()
        self.guest.prepare.assert_called_once()
        self.guest.activate.assert_not_called()
        self.guest.deactivate.assert_called_once()
        self.assertEqual(self.records, [("WSL_BOOT_CANCELLED_BY_OFF", "OFF")])


if __name__ == "__main__":
    unittest.main()
