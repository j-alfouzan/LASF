import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table


console = Console()

GARAK_HOME = (
    Path.home() / ".local" / "share" / "garak" / "garak_runs"
)


def find_garak_python():
    """Find the Python executable in the Garak virtual environment."""
    if os.name == "nt":
        candidate = (
            Path.home() / ".venv-garak" / "Scripts" / "python.exe"
        )
    else:
        candidate = Path.home() / ".venv-garak" / "bin" / "python"

    if not candidate.is_file():
        raise FileNotFoundError(
            f"Garak environment not found: {candidate}"
        )

    return str(candidate)


def normalize_scores(scores):
    """Normalize detector scores into a list."""
    if scores is None:
        return []

    if isinstance(scores, list):
        return scores

    return [scores]


def parse_report(report_path):
    """Read Garak JSONL and extract evaluated attempts."""
    attempts = []

    with report_path.open("r", encoding="utf-8") as file:
        for number, line in enumerate(file, 1):
            if not line.strip():
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON on line {number}"
                ) from exc

            if record.get("entry_type") != "attempt":
                continue

            detectors = record.get("detector_results") or {}

            if record.get("status") != 2 or not detectors:
                continue

            outputs = record.get("outputs") or []
            output = outputs[0] if outputs else {}

            generation_count = max(
                (
                    len(normalize_scores(scores))
                    for scores in detectors.values()
                ),
                default=0,
            )

            if isinstance(output, dict):
                output_text = output.get("text", "")
            else:
                output_text = str(output)

            attempts.append({
                "source": "garak",
                "probe": record.get(
                    "probe_classname",
                    "unknown",
                ),
                "attempt_id": record.get("uuid"),
                "status_code": record.get("status"),
                "prompt": record.get("prompt"),
                "output": output_text,
                "detector_results": detectors,
                "generation_count": generation_count,
                "intent": record.get("intent"),
                "security_finding": "undetermined",
            })

    return attempts


def run_garak(
    model_name,
    probe_spec="test.Test",
    generations=1,
    timeout=1800,
):
    """Run Garak and return structured assessment results."""
    if not model_name.strip():
        raise ValueError("Model name must not be empty")

    if generations < 1:
        raise ValueError("Generations must be at least 1")

    GARAK_HOME.mkdir(parents=True, exist_ok=True)

    python_exe = find_garak_python()

    existing_reports = {
        path.resolve()
        for path in GARAK_HOME.glob("*.report.jsonl")
    }

    normalized_probe = probe_spec.removeprefix("probes.")

    command = [
        python_exe,
        "-m",
        "garak",
        "--model_type",
        "huggingface",
        "--model_name",
        model_name,
        "--probes",
        normalized_probe,
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
            f"Garak timed out after {timeout} seconds"
        ) from exc

    reports = [
        path
        for path in GARAK_HOME.glob("*.report.jsonl")
        if path.resolve() not in existing_reports
    ]

    if not reports:
        raise RuntimeError(
            f"No new Garak report was generated. "
            f"Exit code: {completed.returncode}\n"
            f"{completed.stderr[-3000:]}\n"
            f"{completed.stdout[-3000:]}"
        )

    report_path = max(
        reports,
        key=lambda path: path.stat().st_mtime,
    )

    attempts = parse_report(report_path)

    evaluated_generations = sum(
        attempt.get("generation_count", 0)
        for attempt in attempts
    )

    return {
        "source": "garak",
        "model": model_name,
        "probe_spec": normalized_probe,
        "requested_generations": generations,
        "started_at": started_at,
        "return_code": completed.returncode,
        "report_path": str(report_path),
        "attempt_count": len(attempts),
        "evaluated_generations": evaluated_generations,
        "attempts": attempts,
        "stdout": completed.stdout[-3000:],
        "stderr": completed.stderr[-3000:],
    }


def format_score(score):
    """Format a detector score for terminal display."""
    if isinstance(score, (int, float)):
        return f"{score:.2f}"

    return str(score)


def collect_detector_results(attempts):
    """Group detector scores by probe and detector."""
    results = {}

    for attempt in attempts:
        probe = attempt["probe"]

        for detector, raw_scores in attempt["detector_results"].items():
            key = (probe, detector)

            results.setdefault(key, []).extend(
                normalize_scores(raw_scores)
            )

    return results


def display_report(result):
    """Display a readable assessment report in the terminal."""

    # Plain text heading also makes the output testable.
    console.print("LSAF / GARAK ASSESSMENT")

    console.print(
        Panel(
            "[bold cyan]LSAF[/bold cyan] "
            "[dim]/[/dim] "
            "[bold white]GARAK SECURITY ASSESSMENT[/bold white]",
            border_style="cyan",
            box=box.DOUBLE,
            padding=(1, 2),
        )
    )

    # Assessment configuration
    config = Table(
        title="ASSESSMENT CONFIGURATION",
        box=box.ROUNDED,
        border_style="cyan",
        show_header=False,
        padding=(0, 2),
        expand=True,
    )

    config.add_column("Property", style="dim", width=22)
    config.add_column("Value", style="white")

    config.add_row("Target model", str(result.get("model", "-")))
    config.add_row("Scanner", "Garak")
    config.add_row("Probe", str(result.get("probe_spec", "-")))
    config.add_row(
        "Requested generations",
        str(result.get("requested_generations", "-")),
    )
    config.add_row("Started at", str(result.get("started_at", "-")))

    console.print(config)

    # Scan summary
    console.print()
    console.print("SCAN SUMMARY")

    summary = Table(
        title="SCAN SUMMARY",
        box=box.ROUNDED,
        border_style="cyan",
        padding=(0, 2),
        expand=True,
    )

    summary.add_column("Metric", style="dim")
    summary.add_column("Result", justify="right", style="bold white")

    summary.add_row(
        "Evaluated attempts",
        str(result.get("attempt_count", 0)),
    )
    summary.add_row(
        "Evaluated generations",
        str(result.get("evaluated_generations", 0)),
    )
    summary.add_row(
        "Garak exit code",
        str(result.get("return_code", "-")),
    )

    console.print(summary)

    # Detector results
    console.print()

    detector_results = collect_detector_results(
        result.get("attempts", [])
    )

    console.print("DETECTOR RESULTS")

    detector_table = Table(
        title="DETECTOR RESULTS",
        box=box.ROUNDED,
        border_style="cyan",
        padding=(0, 1),
        expand=True,
    )

    detector_table.add_column("Probe", style="white")
    detector_table.add_column("Detector", style="cyan")
    detector_table.add_column("Scores", overflow="fold")
    detector_table.add_column("Count", justify="right")
    detector_table.add_column("Average", justify="right")

    if detector_results:
        for (probe, detector), scores in detector_results.items():
            numeric_scores = [
                score
                for score in scores
                if isinstance(score, (int, float))
            ]

            average = (
                sum(numeric_scores) / len(numeric_scores)
                if numeric_scores
                else None
            )

            formatted_scores = ", ".join(
                format_score(score)
                for score in scores
            )

            detector_table.add_row(
                probe,
                detector,
                formatted_scores or "-",
                str(len(scores)),
                f"{average:.2f}" if average is not None else "-",
            )
    else:
        detector_table.add_row(
            "-", "-", "No evaluated detector results", "0", "-"
        )

    console.print(detector_table)

    # Individual attempts
    console.print()

    attempt_table = Table(
        title="ATTEMPT DETAILS",
        box=box.ROUNDED,
        border_style="cyan",
        padding=(0, 1),
        expand=True,
    )

    attempt_table.add_column("#", justify="right", style="dim")
    attempt_table.add_column("Probe", style="white")
    attempt_table.add_column("Status", justify="center")
    attempt_table.add_column("Generations", justify="right")
    attempt_table.add_column("Detectors", overflow="fold")

    attempts = result.get("attempts", [])

    if attempts:
        for index, attempt in enumerate(attempts, 1):
            detector_names = ", ".join(
                attempt.get("detector_results", {}).keys()
            )

            attempt_table.add_row(
                str(index),
                str(attempt.get("probe", "-")),
                str(attempt.get("status_code", "-")),
                str(attempt.get("generation_count", 0)),
                detector_names or "-",
            )
    else:
        attempt_table.add_row(
            "-", "-", "-", "-", "No evaluated attempts"
        )

    console.print(attempt_table)

    # Raw report location
    console.print()

    console.print(
        Panel(
            str(result.get("report_path", "-")),
            title="RAW GARAK REPORT (JSONL)",
            border_style="dim",
            box=box.ROUNDED,
        )
    )

    # Completion status
    console.print()

    if result.get("return_code") == 0:
        console.print("SCAN COMPLETED")

        console.print(
            Panel(
                "[bold green]SCAN COMPLETED[/bold green]\n"
                "[dim]Garak finished successfully.[/dim]",
                border_style="green",
                box=box.ROUNDED,
            )
        )
    else:
        console.print("SCAN FAILED")
        console.print(f"Exit code: {result.get('return_code', '-')}")

        console.print(
            Panel(
                "[bold red]SCAN FAILED[/bold red]\n"
                f"Exit code: {result.get('return_code', '-')}",
                border_style="red",
                box=box.ROUNDED,
            )
        )

        if result.get("stderr"):
            console.print(
                Panel(
                    result["stderr"],
                    title="ERROR DETAILS",
                    border_style="red",
                    box=box.ROUNDED,
                )
            )

    console.print(
        "[dim]Note: Detector scores are tool outputs, "
        "not standalone confirmation of a vulnerability.[/dim]"
    )
    console.print()


def main():
    parser = argparse.ArgumentParser(
        description="Run a Garak assessment through LSAF"
    )

    parser.add_argument(
        "--model",
        default="gpt2",
        help="Hugging Face model name",
    )
    parser.add_argument(
        "--probes",
        default="test.Test",
        help="Garak probe specification",
    )
    parser.add_argument(
        "--generations",
        type=int,
        default=1,
        help="Number of generations per probe",
    )

    args = parser.parse_args()

    try:
        result = run_garak(
            args.model,
            args.probes,
            args.generations,
        )

        display_report(result)

        sys.exit(
            0 if result["return_code"] == 0 else 1
        )

    except (
        FileNotFoundError,
        ValueError,
        RuntimeError,
    ) as exc:
        console.print(
            Panel(
                str(exc),
                title="LSAF ERROR",
                border_style="red",
                box=box.ROUNDED,
            )
        )
        sys.exit(1)


if __name__ == "__main__":
    main()