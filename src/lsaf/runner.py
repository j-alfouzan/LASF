import json
from datetime import datetime
from pathlib import Path

from .client import LLMClient
from .probes import PROBES
from .target import Target


def run_assessment(target: Target):
    started_at = datetime.now().astimezone().isoformat()
    client = LLMClient(
        endpoint=target.endpoint,
        model=target.model,
    )

    results = []

    for probe in PROBES:
        results.append(probe.execute(target, client))

    executed = [item for item in results if item["status"] != "not_executed"]
    failed = [item for item in results if item["status"] == "fail"]
    errors = [item for item in results if item["status"] == "error"]

    report = {
        "project": "LSAF",
        "report_type": "Live LLM Assessment",
        "started_at": started_at,
        "target": {
            "name": target.name,
            "endpoint": target.endpoint,
            "model": target.model,
        },
        "owasp_edition": "2025",
        "status": (
            "completed_with_errors" if errors
            else "completed"
        ),
        "tests_executed": len(executed),
        "tests_not_executed": len(results) - len(executed),
        "tests_failed": len(failed),
        "tests": results,
        "limitations": [
            "Only implemented probes are executed against the live model.",
            "The initial pass/fail classification uses simple response heuristics.",
            "Results require human review and do not establish overall model security.",
        ],
    }

    project_root = Path(__file__).resolve().parents[2]
    reports_dir = project_root / "Reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = reports_dir / f"lsaf_report_{timestamp}.json"
    md_path = reports_dir / f"lsaf_report_{timestamp}.md"

    report["report_files"] = {
        "json": str(json_path),
        "markdown": str(md_path),
    }

    json_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    lines = [
        "# LSAF Security Assessment Report",
        "",
        f"- Started: {started_at}",
        f"- Target: {target.name}",
        f"- Endpoint: {target.endpoint}",
        f"- Model: {target.model}",
        "- OWASP mapping: LLM01 — Prompt Injection (2025 edition)",
        "- Assessment type: Live local-model test",
        f"- Tests executed: {report['tests_executed']}",
        f"- Tests not executed: {report['tests_not_executed']}",
        f"- Tests classified as failed: {report['tests_failed']}",
        "",
        "## Test Results",
        "",
    ]

    for item in results:
        lines.extend([
            f"### {item['probe']}",
            "",
            f"- Category: {item['owasp_category']}",
            f"- Status: {item['status']}",
            f"- Expected behavior: {item['expected_behavior']}",
            f"- Analysis: {item['analysis']}",
            "",
        ])

        if item.get("test_input"):
            lines.extend([
                "**Test input:**",
                "",
                "```text",
                item["test_input"],
                "```",
                "",
            ])

        if item.get("response") is not None:
            lines.extend([
                "**Model response:**",
                "",
                "```text",
                item["response"],
                "```",
                "",
            ])

    lines.extend([
        "## Limitations",
        "",
        *[f"- {item}" for item in report["limitations"]],
        "",
    ])

    md_path.write_text("\n".join(lines), encoding="utf-8")

    return report