#!/usr/bin/env python3
"""
DOMINION - Ultra-Powered Domain Recon Framework
Banner module
"""

from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from rich.align import Align
from rich import box

console = Console()

BANNER = r"""
██████╗  ██████╗ ███╗   ███╗██╗███╗   ██╗██╗ ██████╗ ███╗   ██╗
██╔══██╗██╔═══██╗████╗ ████║██║████╗  ██║██║██╔═══██╗████╗  ██║
██║  ██║██║   ██║██╔████╔██║██║██╔██╗ ██║██║██║   ██║██╔██╗ ██║
██║  ██║██║   ██║██║╚██╔╝██║██║██║╚██╗██║██║██║   ██║██║╚██╗██║
██████╔╝╚██████╔╝██║ ╚═╝ ██║██║██║ ╚████║██║╚██████╔╝██║ ╚████║
╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝
"""

VERSION = "1.0.0"
AUTHOR  = "DOMINION Framework"
TAGLINE = "Ultra-Powered Domain Recon · 12 Phases · Zero Mercy"


def print_banner() -> None:
    """Print the main DOMINION banner."""
    console.print(Text(BANNER, style="bold red"))

    info = (
        f"[bold white]Version:[/bold white] [cyan]{VERSION}[/cyan]   "
        f"[bold white]Author:[/bold white] [cyan]{AUTHOR}[/cyan]   "
        f"[bold white]Mode:[/bold white] [cyan]FULL BEAST[/cyan]"
    )

    tagline_text = f"[bold yellow]⚡ {TAGLINE} ⚡[/bold yellow]"

    panel = Panel(
        Align.center(f"{tagline_text}\n\n{info}"),
        box=box.DOUBLE_EDGE,
        border_style="bold red",
        padding=(1, 4),
    )
    console.print(panel)
    console.print()


def print_phase_banner(phase_num: int, phase_name: str, description: str) -> None:
    """Print a phase start banner."""
    console.rule(f"[bold red]● PHASE {phase_num:02d}[/bold red] [bold white]{phase_name}[/bold white]", style="red")
    console.print(f"[dim]  {description}[/dim]")
    console.print()


def print_phase_done(phase_num: int, phase_name: str, findings: int) -> None:
    """Print a phase completion banner."""
    console.rule(
        f"[bold green]✓ PHASE {phase_num:02d} DONE[/bold green] "
        f"[white]{phase_name}[/white] "
        f"[dim]— {findings} findings[/dim]",
        style="green",
    )
    console.print()


def print_summary_box(domain: str, total_phases: int, total_findings: dict) -> None:
    """Print a final summary box."""
    lines = [f"[bold cyan]Target:[/bold cyan] [yellow]{domain}[/yellow]", ""]
    for phase, count in total_findings.items():
        color = "green" if count > 0 else "dim"
        lines.append(f"  [{color}]{'●' if count > 0 else '○'}[/{color}] {phase}: [bold]{count}[/bold]")
    lines.append("")
    lines.append(f"[bold green]✓ Completed {total_phases} phases[/bold green]")

    panel = Panel(
        "\n".join(lines),
        title="[bold red]🔥 DOMINION COMPLETE[/bold red]",
        border_style="red",
        box=box.DOUBLE_EDGE,
        padding=(1, 3),
    )
    console.print(panel)
