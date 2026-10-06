from pathlib import Path
from unittest import result

import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align

from .config import PROJECT_NAME, VERSION


app = typer.Typer(
    name="lsaf",
    help="LLM Security Assessment Framework",
    add_completion=False,
)

console = Console()


def show_banner():
    banner_path = Path(__file__).parent / "assets" / "banner.txt"
    banner = banner_path.read_text(encoding="utf-8").strip()

    logo = Text(banner, style="bold bright_green")

    info = Text()

    info.append("LSAF\n", style="bold bright_green")
    info.append(
        "LLM Security Assessment Framework\n\n",
        style="bold white",
    )

    info.append("VERSION   ", style="bold bright_green")
    info.append(VERSION, style="white")

    info.append("     PLATFORM   ", style="bold bright_green")
    info.append("Kali Linux", style="white")

    info.append("\n\n")

    info.append("MODE   ", style="bold bright_green")
    info.append("Security Assessment", style="white")

    info.append("     ENGINE   ", style="bold bright_green")
    info.append("ONLINE", style="bold bright_green")

    info.append("     STATUS   ", style="bold bright_green")
    info.append("READY", style="bold bright_green")

    info_box = Panel(
        Align.center(info),
        border_style="bright_green",
        padding=(1, 3),
        width=72,
    )

    console.print()
    console.print(Align.center(logo))
    console.print()
    console.print(Align.center(info_box))
    console.print()

    console.print(
        Align.center(
            Text(
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
                style="bright_green",
            )
        )
    )

    console.print(
        Align.center(
            Text(
                "LSAF  •  LLM SECURITY ASSESSMENT FRAMEWORK",
                style="bold bright_green",
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
    console.print(
        f"[bold bright_green]{PROJECT_NAME}[/bold bright_green] "
        f"v{VERSION}"
    )
@app.command()
def scan():
    """Start an LLM security assessment."""
    console.print()
    console.print("[bold bright_green]LSAF SCAN[/bold bright_green]")
    console.print("[dim]Initializing security assessment...[/dim]")
    console.print()
    console.print("[bright_green][+] Assessment engine ready[/bright_green]")
    console.print("[bright_green][+] Test environment ready[/bright_green]")
    console.print("[bright_green][+] Waiting for assessment modules[/bright_green]")
    console.print()

@app.command()
def probes():
    """List available assessment probes."""
    console.print()
    console.print("[bold bright_green]LSAF PROBES[/bold bright_green]")
    console.print()
    
    console.print("[bright_green]Available Probes[/bright_green]")
    console.print("  [white]• Prompt Injection[/white]")
    console.print("  [white]• Jailbreak Testing[/white]")
    console.print("  [white]• Guardrail Bypass[/white]")
    
    console.print()
    console.print(
        "[dim] Custom probes will be added to the assessment engine.[/dim]"
    )
    console.print()
@app.command()
def scan(target: str = "local"):
    """Run an LSAF security assessment."""
    from .runner import run_assessment
    console.print()
    console.print("LSAF SCAN", style="bold bright_green")
    console.print()
    
    console.print(f"Target: {target}")
    console.print("Starting assessment...", style="bright_green")

    result = run_assessment(target)

    console.print()
    console.print("Executed Probes", style="bright_green")
    
    for test in result["tests"]:
        console.print(
            f" • {test['probe']} — {test['status']}",
            style="white",     
        )       
    console.print()
    console.print(
         f"Assessment status: {result['status'].upper()}",
         style="bold bright_green",
    )
    console.print(f"Target: {result['target']}")
    console.print(f"Started: {result['started_at']}")
    console.print()

if __name__ == "__main__":
    app()