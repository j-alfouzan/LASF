
import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()
GARAK_HOME = Path.home() / ".local" / "share" / "garak" / "garak_runs"


def find_garak_python():
    if os.name == "nt":
        candidate = Path.home() / ".venv-garak" / "Scripts" / "python.exe"
    else:
        candidate = Path.home() / ".venv-garak" / "bin" / "python"

    if not candidate.is_file():
        raise FileNotFoundError(f"Garak environment not found: {candidate}")

    return str(candidate)


def parse_report(report_path):
    attempts = []

    with report_path.open("r", encoding="utf-8") as file:
        for number, line in enumerate(file, 1):
            if not line.strip():
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {number}") from exc

            if record.get("entry_type") != "attempt":
                continue

            detectors = record.get("detector_results") or {}

            if record.get("status") != 2 or not detectors:
                continue

            outputs = record.get("outputs") or []
            output = outputs[0] if outputs else {}

            attempts.append({
                "source": "garak",
                "probe": record.get("probe_classname", "unknown"),
                "attempt_id": record.get("uuid"),
                "status_code": record.get("status"),
                "prompt": record.get("prompt"),
                "output": (
                    output.get("text", "")
                    if isinstance(output, dict)
                    else str(output)
                ),
                "detector_results": detectors,
                "intent": record.get("intent"),
                "security_finding": "undetermined",
            })

    return attempts


def run_garak(
    model_name,
    probe_spec="probes.test.Test",
    generations=1,
    timeout=1800,
):
    if not model_name.strip():
        raise ValueError("Model name must not be empty")

    if generations < 1:
        raise ValueError("Generations must be at least 1")

    GARAK_HOME.mkdir(parents=True, exist_ok=True)
    python_exe = find_garak_python()

    existing = {
        p.resolve()
        for p in GARAK_HOME.glob("*.report.jsonl")
    }

    command = [
        python_exe,
        "-m", "garak",
        "--target_type", "huggingface",
        "--target_name", model_name,
        "--probes", probe_spec,
        "--generations", str(generations),
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
        p for p in GARAK_HOME.glob("*.report.jsonl")
        if p.resolve() not in existing
    ]

    if not reports:
        raise RuntimeError(
            f"No new Garak report. Exit code: {completed.returncode}\n"
            f"{completed.stderr[-3000:]}"
        )

    report_path = max(reports, key=lambda p: p.stat().st_mtime)
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


def display_report(result):
    console.print()
    console.print(
        "[bold cyan]LSAF[/bold cyan] [dim]/[/dim] "
        "[bold white]GARAK ASSESSMENT[/bold white]"
    )
    console.print("[dim]" + "─" * 58 + "[/dim]")

    config = Table(
        box=box.SIMPLE,
        show_header=False,
        padding=(0, 2),
    )
    config.add_column("PROPERTY", style="dim", width=18)
    config.add_column("VALUE", style="white")

    config.add_row("MODEL", result["model"])
    config.add_row("SCANNER", "Garak")
    config.add_row("PROBE", result["probe_spec"])
    config.add_row("STARTED", result["started_at"])

    console.print(config)

    console.print()
    console.print("[bold cyan]01 / SCAN SUMMARY[/bold cyan]")

    summary = Table(
        box=box.SIMPLE_HEAD,
        padding=(0, 2),
        header_style="dim",
    )
    summary.add_column("EVALUATED ATTEMPTS")
    summary.add_column("RETURN CODE")

    summary.add_row(
        str(result["attempt_count"]),
        str(result["return_code"]),
    )

    console.print(summary)

    console.print()
    console.print("[bold cyan]02 / DETECTOR RESULTS[/bold cyan]")

    detectors = Table(
        box=box.SIMPLE_HEAD,
        padding=(0, 1),
        header_style="bold cyan",
    )
    detectors.add_column("PROBE")
    detectors.add_column("DETECTOR")
    detectors.add_column("SCORES")

    rows = {}

    for attempt in result["attempts"]:
        for name, scores in attempt["detector_results"].items():
            key = (attempt["probe"], name)
            rows.setdefault(key, []).extend(
                scores if isinstance(scores, list) else [scores]
            )

    if rows:
        for (probe, detector), scores in rows.items():
            formatted_scores = ", ".join(
                f"{score:.2f}"
                if isinstance(score, (int, float))
                else str(score)
                for score in scores
            )
            detectors.add_row(probe, detector, formatted_scores)
    else:
        detectors.add_row("-", "-", "No results")

    console.print(detectors)

    console.print()
    console.print("[dim]REPORT LOCATION[/dim]")
    console.print(f"[cyan]{result['report_path']}[/cyan]")

    console.print()
    if result["return_code"] == 0:
        console.print(
            "[bold green]SCAN COMPLETED[/bold green] "
            "[dim]Exit code: 0[/dim]"
        )
    else:
        console.print(
            "[bold red]SCAN FAILED[/bold red] "
            f"[dim]Exit code: {result['return_code']}[/dim]"
        )

        if result["stderr"]:
            console.print(
                Panel(
                    result["stderr"],
                    title="ERROR",
                    border_style="red",
                    box=box.SIMPLE,
                )
            )

    console.print("[dim]" + "─" * 58 + "[/dim]")
    console.print()


def main():
    parser = argparse.ArgumentParser(
        description="Run Garak assessment"
    )
    parser.add_argument("--model", default="gpt2")
    parser.add_argument("--probes", default="probes.test.Test")
    parser.add_argument("--generations", type=int, default=1)
    args = parser.parse_args()

    try:
        result = run_garak(
            args.model,
            args.probes,
            args.generations,
        )
        display_report(result)
        sys.exit(0 if result["return_code"] == 0 else 1)

    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        console.print(f"[bold red]ERROR[/bold red] {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
