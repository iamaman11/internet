"""One-shot VM installer source-sync tests (no network, no credentials)."""
import importlib.util
import io
from pathlib import Path
import sys
import tarfile
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
spec = importlib.util.spec_from_file_location("s1_installer", TOOLS / "install_vm.py")
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)

OLD = "a" * 40
NEW = "b" * 40


def identity(sha=OLD):
    return installer.VM_HOSTNAME + "\n0\n" + sha


class InstallerSyncTests(unittest.TestCase):
    def test_matching_sha_no_fetch_or_merge(self):
        with patch.object(installer, "ssh", side_effect=[
            identity(NEW), installer.ORIGIN, "",
        ]) as call:
            installer.sync_source(NEW)
            self.assertEqual(call.call_count, 3)
            self.assertNotIn("fetch", " ".join(x.args[0] for x in call.call_args_list))

    def test_remote_repository_mismatch_refused(self):
        with patch.object(installer, "ssh", side_effect=[
            identity(), "https://github.com/other/project.git",
        ]) as call:
            with self.assertRaisesRegex(RuntimeError, "VM_REPOSITORY_MISMATCH"):
                installer.sync_source(NEW)
            self.assertEqual(call.call_count, 2)

    def test_remote_identity_mismatch_refused(self):
        with patch.object(installer, "ssh", return_value="other-host\n0\n" + OLD) as call:
            with self.assertRaisesRegex(RuntimeError, "VM_IDENTITY_MISMATCH"):
                installer.sync_source(NEW)
            self.assertEqual(call.call_count, 1)

    def test_dirty_remote_checkout_refused(self):
        with patch.object(installer, "ssh", side_effect=[
            identity(), installer.ORIGIN, " M vm/compose.yaml",
        ]) as call:
            with self.assertRaisesRegex(RuntimeError, "VM_SOURCE_DIRTY"):
                installer.sync_source(NEW)
            self.assertEqual(call.call_count, 3)

    def test_ff_only_update_verified(self):
        with patch.object(installer, "ssh", side_effect=[
            identity(), installer.ORIGIN, "", "", NEW, "", NEW,
        ]) as call:
            installer.sync_source(NEW)
            commands = [x.args[0] for x in call.call_args_list]
            self.assertEqual(call.call_count, 7)
            self.assertIn("fetch --quiet origin main", commands[3])
            self.assertIn("merge --ff-only FETCH_HEAD", commands[5])
            self.assertIn("rev-parse HEAD", commands[6])

    def test_wrong_fetch_sha_stops_before_merge(self):
        with patch.object(installer, "ssh", side_effect=[
            identity(), installer.ORIGIN, "", "", OLD,
        ]) as call:
            with self.assertRaisesRegex(RuntimeError, "VM_FETCH_HEAD_MISMATCH"):
                installer.sync_source(NEW)
            self.assertEqual(call.call_count, 5)

    def test_non_fast_forward_stops_without_reset(self):
        with patch.object(installer, "ssh", side_effect=[
            identity(), installer.ORIGIN, "", "", NEW,
            RuntimeError("REMOTE_OPERATION_FAILED"),
        ]) as call:
            with self.assertRaisesRegex(RuntimeError, "REMOTE_OPERATION_FAILED"):
                installer.sync_source(NEW)
            commands = " ".join(x.args[0] for x in call.call_args_list)
            self.assertNotIn("reset", commands)
            self.assertEqual(call.call_count, 6)

    def test_failed_readback_is_not_pass(self):
        with patch.object(installer, "ssh", side_effect=[
            identity(), installer.ORIGIN, "", "", NEW, "", OLD,
        ]) as call:
            with self.assertRaisesRegex(RuntimeError, "VM_SOURCE_UPDATE_UNVERIFIED"):
                installer.sync_source(NEW)
            self.assertEqual(call.call_count, 7)

    def test_scoped_archive_never_touches_line1_runtime(self):
        data = installer.archive({
            "line1.json": '{"value":"unchanged"}',
            "line2.json": '{"value":"updated"}',
        }, only="line2")
        with tarfile.open(fileobj=io.BytesIO(data)) as tar:
            self.assertEqual(tar.getnames(), ["runtime", "runtime/line2.json"])
            self.assertEqual(tar.getmember("runtime").mode, 0o700)
            self.assertEqual(tar.getmember("runtime/line2.json").mode, 0o600)


    def test_pinned_sing_box_image(self):
        self.assertIn("@sha256:", installer.line2_image())

    def test_scoped_recreate_checks_neighbors_and_native_config(self):
        warp, line1, old, new = ("a" * 64, "b" * 64, "c" * 64, "d" * 64)
        with patch.object(installer, "ssh", side_effect=[
            warp + " true", line1 + " true", old + " true",
            "", "", new + " true", warp + " true", line1 + " true",
            "healthy",
        ]) as call:
            installer.apply_line2()
            commands = [x.args[0] for x in call.call_args_list]
            self.assertEqual(len(commands), 9)
            self.assertIn("--network none", commands[3])
            self.assertIn(" check -c /etc/sing-box/config.json", commands[3])
            self.assertIn("--no-deps --force-recreate line2-proxy", commands[4])
            self.assertNotIn("--force-recreate warp-egress", " ".join(commands))
            self.assertNotIn("--force-recreate line1-gateway", " ".join(commands))

    def test_failed_native_check_never_recreates_service(self):
        with patch.object(installer, "ssh", side_effect=[
            "a" * 64 + " true", "b" * 64 + " true",
            "c" * 64 + " true", RuntimeError("REMOTE_OPERATION_FAILED"),
        ]) as call:
            with self.assertRaisesRegex(RuntimeError, "REMOTE_OPERATION_FAILED"):
                installer.apply_line2()
            commands = " ".join(x.args[0] for x in call.call_args_list)
            self.assertNotIn("--force-recreate", commands)
            self.assertEqual(call.call_count, 4)

    def test_stopped_neighbor_blocks_apply(self):
        with patch.object(installer, "ssh", return_value="a" * 64 + " false") as call:
            with self.assertRaisesRegex(RuntimeError, "CONTAINER_NOT_RUNNING"):
                installer.apply_line2()
            self.assertEqual(call.call_count, 1)

    def test_neighbor_identity_change_is_not_pass(self):
        with patch.object(installer, "ssh", side_effect=[
            "a" * 64 + " true", "b" * 64 + " true", "c" * 64 + " true",
            "", "", "d" * 64 + " true", "e" * 64 + " true",
        ]) as call:
            with self.assertRaisesRegex(RuntimeError, "UNRELATED_CONTAINER_CHANGED"):
                installer.apply_line2()
            self.assertEqual(call.call_count, 7)

    def test_no_recreate_receipt_rejected(self):
        with patch.object(installer, "ssh", side_effect=[
            "a" * 64 + " true", "b" * 64 + " true", "c" * 64 + " true",
            "", "", "c" * 64 + " true",
        ]) as call:
            with self.assertRaisesRegex(RuntimeError, "LINE2_NOT_RECREATED"):
                installer.apply_line2()
            self.assertEqual(call.call_count, 6)


if __name__ == "__main__":
    unittest.main()
