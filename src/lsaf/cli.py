from pathlib import Path

import typer
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from .config import PROJECT_NAME, VERSION
from .probes import PROBES

app = typer.Typer(
    name="lsaf",
    help="LLM Security Assessment Framework",
    add_completion=False,
)
console = Console()


def show_banner():
    banner_path = Path(__file__).parent / "assets" / "banner.txt"
    banner = (
        banner_path.read_text(encoding="utf-8").strip()
        if banner_path.exists()
        else "LSAF"
    )

    info = Text()
    info.append("LSAF\n", style="bold bright_green")
    info.append("LLM Security Assessment Framework\n\n", style="bold white")
    info.append("VERSION   ", style="bold bright_green")
    info.append(VERSION, style="white")
    info.append("     MODE   ", style="bold bright_green")
    info.append("Live Model Assessment", style="white")

    console.print()
    console.print(Align.center(Text(banner, style="bold bright_green")))
    console.print()
    console.print(
        Align.center(
            Panel(
                Align.center(info),
                border_style="bright_green",
                padding=(1, 3),
                width=72,
            )
        )
    )
    console.print()


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        show_banner()


@app.command()
def version():
    """Show LSAF version."""
    console.print(f"[bold bright_green]{PROJECT_NAME}[/bold bright_green] v{VERSION}")


@app.command()
def probes():
    """List registered assessment probes."""
    console.print("\n[bold bright_green]LSAF PROBES[/bold bright_green]\n")
    for probe in PROBES:
        console.print(f"[bold white]{probe.name}[/bold white]")
        console.print(f"  OWASP category: {probe.category}")
        console.print(f"  {probe.description}\n")


@app.command()
def scan(
    name: str = typer.Option("Local Ollama Model", help="Target name"),
    endpoint: str = typer.Option("http://localhost:11434", help="Ollama endpoint"),
    model: str = typer.Option("qwen2.5:0.5b", help="Ollama model identifier"),
):
    """Run implemented probes against a local Ollama model."""
    from .runner import run_assessment
    from .target import Target

    target = Target(name=name, endpoint=endpoint, model=model)

    console.print("\n[bold bright_green]LSAF LIVE SCAN[/bold bright_green]\n")
    console.print(f"Target: {target.name}")
    console.print(f"Endpoint: {target.endpoint}")
    console.print(f"Model: {target.model}\n")
    console.print("[yellow]Connecting to Ollama and running implemented probes...[/yellow]\n")

    report = run_assessment(target)

    for test in report["tests"]:
        status = test["status"].upper()
        color = "red" if status in ("FAIL", "ERROR") else (
            "green" if status == "PASS" else "yellow"
        )
        console.print(f"[bold]{test['probe']}[/bold] — [{color}]{status}[/{color}]")
        console.print(f"  {test['analysis']}\n")

    console.print("[bold bright_green]Reports saved[/bold bright_green]")
    console.print(f"JSON: {report['report_files']['json']}")
    console.print(f"Markdown: {report['report_files']['markdown']}\n")


if __name__ == "__main__":
    app()