
"""Run Garak as an external process and parse its JSONL report."""

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


GARAK_HOME = Path.home() / ".local" / "share" / "garak" / "garak_runs"


def find_garak_python() -> str:
    """Find the Python executable in the dedicated Garak environment."""
    if os.name == "nt":
        candidate = Path.home() / ".venv-garak" / "Scripts" / "python.exe"
    else:
        candidate = Path.home() / ".venv-garak" / "bin" / "python"

    if not candidate.is_file():
        raise FileNotFoundError(
            f"Garak Python environment not found: {candidate}"
        )

    return str(candidate)


def parse_report(report_path: Path) -> list[dict]:
    """Read Garak JSONL and return normalized attempt records."""
    attempts = []

    with report_path.open("r", encoding="utf-8") as report_file:
        for line_number, line in enumerate(report_file, start=1):
            if not line.strip():
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON on report line {line_number}"
                ) from exc

            if record.get("entry_type") != "attempt":
                continue

            # Keep only evaluated attempts to avoid counting each attempt twice.
            detector_results = record.get("detector_results") or {}
            if record.get("status") != 2 or not detector_results:
                continue

            outputs = record.get("outputs") or []
            first_output = outputs[0] if outputs else {}
            output_text = (
                first_output.get("text", "")
                if isinstance(first_output, dict)
                else str(first_output)
            )

            attempts.append(
                {
                    "source": "garak",
                    "probe": record.get("probe_classname", "unknown"),
                    "attempt_id": record.get("uuid"),
                    "status_code": record.get("status"),
                    "prompt": record.get("prompt"),
                    "output": output_text,
                    "detector_results": detector_results,
                    "intent": record.get("intent"),
                    "security_finding": "undetermined",
                }
            )
    return attempts


def run_garak(
    model_name: str,
    probe_spec: str = "probes.test.Test",
    generations: int = 1,
    timeout: int = 1800,
) -> dict:
    """Run Garak against a Hugging Face model and parse its new report."""
    if not model_name.strip():
        raise ValueError("model_name must not be empty")

    if generations < 1:
        raise ValueError("generations must be at least 1")

    python_exe = find_garak_python()
    GARAK_HOME.mkdir(parents=True, exist_ok=True)

    # Snapshot existing reports so we can identify the report from this run.
    existing_reports = {
        path.resolve()
        for path in GARAK_HOME.glob("*.report.jsonl")
    }

    command = [
        python_exe,
        "-m",
        "garak",
        "--target_type",
        "huggingface",
        "--target_name",
        model_name,
        "--probes",
        probe_spec,
        "--generations",
        str(generations),
    ]

    started_at = datetime.now(timezone.utc).isoformat()

    try:
       completed = subprocess.run(
    command,
    capture_output=True,
    text=True,
    encoding="utf-8",
    errors="replace",
    timeout=timeout,
    check=False,
) 
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"Garak exceeded the timeout of {timeout} seconds"
        ) from exc

    new_reports = [
        path
        for path in GARAK_HOME.glob("*.report.jsonl")
        if path.resolve() not in existing_reports
    ]

    if not new_reports:
        raise RuntimeError(
            "Garak finished without producing a new report. "
            f"Exit code: {completed.returncode}\n"
            f"STDERR:\n{completed.stderr[-3000:]}"
        )

    report_path = max(new_reports, key=lambda path: path.stat().st_mtime)
    attempts = parse_report(report_path)

    return {
        "source": "garak",
        "model": model_name,
        "probe_spec": probe_spec,
        "started_at": started_at,
        "return_code": completed.returncode,
        "report_path": str(report_path),
        "attempt_count": len(attempts),
        "attempts": attempts,
        "stdout": completed.stdout[-3000:],
        "stderr": completed.stderr[-3000:],
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run Garak independently")
    parser.add_argument("--model", default="gpt2")
    parser.add_argument("--probes", default="probes.test.Test")
    parser.add_argument("--generations", type=int, default=1)
    args = parser.parse_args()

    try:
        result = run_garak(
            model_name=args.model,
            probe_spec=args.probes,
            generations=args.generations,
        )
        print(json.dumps(result, indent=2, ensure_ascii=False))
        sys.exit(0 if result["return_code"] == 0 else 1)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        print(f"Garak integration error: {exc}", file=sys.stderr)
        sys.exit(1)