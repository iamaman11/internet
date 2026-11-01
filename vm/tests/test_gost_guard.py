"""I16: reject unsafe GOST OUTPUT changes without adding a controller."""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from check_gost_guard import check_guard, check_entrypoint, GUARD, WRAPPER


class GostGuardTests(unittest.TestCase):
    def test_pinned_gost_guard_and_startup(self):
        check_guard(GUARD.read_text(encoding="utf-8"))
        check_entrypoint(WRAPPER.read_text(encoding="utf-8"))

    def test_unrestricted_eth0_rejected(self):
        original = GUARD.read_text(encoding="utf-8")
        unsafe = original.replace('oifname "eth0" ct direction reply accept',
                                  'oifname "eth0" accept')
        with self.assertRaisesRegex(ValueError, "RULES_MISMATCH"):
            check_guard(unsafe)

    def test_established_direct_outbound_rejected(self):
        original = GUARD.read_text(encoding="utf-8")
        unsafe = original.replace('ct direction reply accept',
                                  'ct state established accept')
        with self.assertRaisesRegex(ValueError, "RULES_MISMATCH"):
            check_guard(unsafe)

    def test_wrong_gost_uid_rejected(self):
        original = GUARD.read_text(encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "RULES_MISMATCH"):
            check_guard(original.replace("meta skuid 1000", "meta skuid 0"))

    def test_missing_final_drop_rejected(self):
        original = GUARD.read_text(encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "RULES_MISMATCH"):
            check_guard(original.replace("meta skuid 1000 counter drop", ""))

    def test_no_guard_before_gost_is_rejected(self):
        original = WRAPPER.read_text(encoding="utf-8")
        unsafe = original.replace("exec /entrypoint.sh", "") + "\nexec /entrypoint.sh\n"
        # Merely moving the exec to the bottom does not bypass the check.
        check_entrypoint(unsafe)
        with self.assertRaisesRegex(ValueError, "EXECUTION_CHAIN_MISSING"):
            check_entrypoint(original.replace("sudo nft -f", "sudo echo"))
        with self.assertRaisesRegex(ValueError, "INSTALLED_AFTER_GOST"):
            check_entrypoint(original.replace("exec /entrypoint.sh",
                                             "exec /entrypoint.sh\nsudo nft -f /etc/internet/gost-egress-guard.nft")
                             .replace("if ! sudo nft -f /etc/internet/gost-egress-guard.nft;",
                                      "if ! true;"))


if __name__ == "__main__":
    unittest.main()
