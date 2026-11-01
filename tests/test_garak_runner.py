
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.lsaf.garak_runner import (
    display_report,
    parse_report,
    run_garak,
)


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

        self.assertEqual(parse_report(report_path), [])

    def test_ignores_unevaluated_attempts(self):
        record = self.sample_record()
        record["status"] = 1
        report_path = self.write_report(record)

        self.assertEqual(parse_report(report_path), [])

    def test_ignores_attempts_without_detector_results(self):
        record = self.sample_record()
        record["detector_results"] = {}
        report_path = self.write_report(record)

        self.assertEqual(parse_report(report_path), [])

    def test_rejects_invalid_json(self):
        report_path = self.temp_path / "invalid.report.jsonl"
        report_path.write_text(
            "{invalid json}\n",
            encoding="utf-8",
        )

        with self.assertRaises(ValueError):
            parse_report(report_path)


class TestRunGarak(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.temp_path = Path(self.temp_dir.name)

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
            with self.assertRaisesRegex(RuntimeError, "timed out"):
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
                "No new Garak report",
            ):
                run_garak("gpt2")

    def test_rejects_empty_model_name(self):
        with self.assertRaises(ValueError):
            run_garak("")

    def test_rejects_invalid_generations(self):
        with self.assertRaises(ValueError):
            run_garak(
                model_name="gpt2",
                generations=0,
            )

    @patch("src.lsaf.garak_runner.subprocess.run")
    def test_successful_garak_run_returns_structured_results(
        self,
        mock_run,
    ):
        report_record = {
            "entry_type": "attempt",
            "status": 2,
            "probe_classname": "probes.test.Test",
            "uuid": "success-001",
            "prompt": "Test prompt",
            "outputs": [{"text": "Test output"}],
            "detector_results": {"always.Pass": [False]},
            "intent": "T999test",
        }

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


class TestDisplayReport(unittest.TestCase):

    def sample_result(self):
        return {
            "model": "gpt2",
            "source": "garak",
            "probe_spec": "probes.test.Test",
            "started_at": "2026-11-01T10:00:00",
            "attempt_count": 1,
            "return_code": 0,
            "stderr": "",
            "attempts": [
                {
                    "probe": "probes.test.Test",
                    "detector_results": {
                        "always.Pass": [False],
                    },
                }
            ],
            "report_path": "test.report.jsonl",
        }

    @patch("src.lsaf.garak_runner.console.print")
    def test_displays_report_summary(self, mock_print):
        result = self.sample_result()
        display_report(result)

        output = " ".join(
            str(arg)
            for call in mock_print.call_args_list
            for arg in call.args
        )

        self.assertIn("GARAK ASSESSMENT", output)
        self.assertIn("SCAN SUMMARY", output)
        self.assertIn("DETECTOR RESULTS", output)
        self.assertIn("SCAN COMPLETED", output)

    @patch("src.lsaf.garak_runner.console.print")
    def test_displays_failure_status(self, mock_print):
        result = self.sample_result()
        result["return_code"] = 1
        result["stderr"] = "Test error"

        display_report(result)

        output = " ".join(
            str(arg)
            for call in mock_print.call_args_list
            for arg in call.args
        )

        self.assertIn("SCAN FAILED", output)
        self.assertIn("Exit code: 1", output)


if __name__ == "__main__":
    unittest.main()
