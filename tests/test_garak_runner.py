
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.lsaf.garak_runner import parse_report, run_garak


class TestParseReport(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.temp_path = Path(self.temp_dir.name)

    def write_report(self, record, filename="report.jsonl"):
        report_path = self.temp_path / filename
        report_path.write_text(
            json.dumps(record) + "\n",
            encoding="utf-8",
        )
        return report_path

    def sample_record(self):
        return {
            "entry_type": "attempt",
            "status": 2,
            "probe_classname": "probes.test.Test",
            "uuid": "test-001",
            "prompt": "Test prompt",
            "outputs": [{"text": "Test output"}],
            "detector_results": {"always.Pass": [False]},
            "intent": "T999test",
        }

    def test_parses_evaluated_attempt(self):
        report_path = self.write_report(self.sample_record())

        attempts = parse_report(report_path)

        self.assertEqual(len(attempts), 1)
        self.assertEqual(attempts[0]["source"], "garak")
        self.assertEqual(attempts[0]["probe"], "probes.test.Test")
        self.assertEqual(attempts[0]["output"], "Test output")
        self.assertEqual(
            attempts[0]["security_finding"],
            "undetermined",
        )

    def test_ignores_non_attempt_records(self):
        report_path = self.write_report({
            "entry_type": "run",
            "status": 2,
        })

        attempts = parse_report(report_path)

        self.assertEqual(attempts, [])

    def test_rejects_invalid_json(self):
        report_path = self.temp_path / "invalid.report.jsonl"
        report_path.write_text(
            "{invalid json}\n",
            encoding="utf-8",
        )

        with self.assertRaises(ValueError):
            parse_report(report_path)

    @patch("src.lsaf.garak_runner.subprocess.run")
    def test_timeout_raises_runtime_error(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd="garak",
            timeout=1,
        )

        with patch(
            "src.lsaf.garak_runner.find_garak_python",
            return_value="python.exe",
        ):
            with self.assertRaisesRegex(RuntimeError, "timeout"):
                run_garak("gpt2", timeout=1)

    @patch("src.lsaf.garak_runner.subprocess.run")
    def test_missing_report_raises_runtime_error(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["garak"],
            returncode=0,
            stdout="",
            stderr="",
        )

        with patch(
            "src.lsaf.garak_runner.find_garak_python",
            return_value="python.exe",
        ), patch(
            "src.lsaf.garak_runner.GARAK_HOME",
            new=self.temp_path,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "without producing",
            ):
                run_garak("gpt2")

    @patch("src.lsaf.garak_runner.subprocess.run")
    def test_successful_garak_run_returns_structured_results(
        self,
        mock_run,
    ):
        report_record = self.sample_record()
        report_record["uuid"] = "success-001"

        def fake_run(*args, **kwargs):
            report_path = self.temp_path / "test.report.jsonl"
            report_path.write_text(
                json.dumps(report_record) + "\n",
                encoding="utf-8",
            )

            return subprocess.CompletedProcess(
                args=args,
                returncode=0,
                stdout="Garak run complete",
                stderr="",
            )

        mock_run.side_effect = fake_run

        with patch(
            "src.lsaf.garak_runner.find_garak_python",
            return_value="python.exe",
        ), patch(
            "src.lsaf.garak_runner.GARAK_HOME",
            new=self.temp_path,
        ):
            result = run_garak(
                model_name="gpt2",
                probe_spec="probes.test.Test",
                generations=1,
            )

        self.assertEqual(result["return_code"], 0)
        self.assertEqual(result["model"], "gpt2")
        self.assertEqual(result["source"], "garak")
        self.assertEqual(result["attempt_count"], 1)
        self.assertEqual(len(result["attempts"]), 1)
        self.assertEqual(
            result["attempts"][0]["attempt_id"],
            "success-001",
        )
        self.assertEqual(
            result["attempts"][0]["security_finding"],
            "undetermined",
        )
        mock_run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
