import pathlib
import sys

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from .output import load_findings, write_findings
from .scan import scan as _scan

app = typer.Typer(help="npm malware research scanner — forensic analysis tool")
console = Console()

_SEVERITY_COLOUR = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "dim",
    "UNKNOWN": "white",
}


@app.command()
def scan(
    path: str = typer.Argument(..., help="Local directory or .tgz tarball to scan"),
    output_dir: str = typer.Option(".", "--output-dir", "-o", help="Directory to write findings JSON"),
) -> None:
    """Scan a local directory or .tgz tarball for malicious patterns."""
    out_path = pathlib.Path(output_dir)

    with console.status(f"Scanning [bold]{path}[/bold]…"):
        label, findings = _scan(path)

    if not findings:
        console.print(f"[green]✓[/green] No findings in [bold]{label}[/bold]")
        sys.exit(0)

    table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    table.add_column("Rule", style="bold")
    table.add_column("Severity")
    table.add_column("File")
    table.add_column("Line", justify="right")

    for f in findings:
        colour = _SEVERITY_COLOUR.get(f.severity, "white")
        table.add_row(f.rule_id, f"[{colour}]{f.severity}[/{colour}]", f.file, str(f.line))

    console.print(table)
    console.print(f"[bold]{len(findings)}[/bold] finding(s) in [bold]{label}[/bold]")

    out_file = write_findings(label, findings, out_path)
    console.print(f"Findings written to [bold]{out_file}[/bold]")


@app.command()
def report(
    findings_file: str = typer.Argument(..., help="Path to a findings JSON file"),
) -> None:
    """Pretty-print a saved findings JSON file."""
    path = pathlib.Path(findings_file)
    data = load_findings(path)

    console.print(f"[bold]Package:[/bold] {data['package']}  [bold]Source:[/bold] {data['source']}")

    if not data["findings"]:
        console.print("[green]No findings.[/green]")
        return

    for f in data["findings"]:
        colour = _SEVERITY_COLOUR.get(f.get("severity", "UNKNOWN"), "white")
        title = f"[{colour}]{f['severity']}[/{colour}]  {f['rule_id']}  — {f['file']}:{f['line']}"
        body_lines = [
            f"[dim]Technique:[/dim] {f['technique']}",
            f"[dim]Source ref:[/dim] {f['source_ref']}",
            "",
            f"[bold]Snippet:[/bold]",
            f"[grey50]{f['raw_snippet']}[/grey50]",
        ]
        if f.get("decoded_snippet"):
            body_lines += ["", f"[bold]Decoded:[/bold]", f"[cyan]{f['decoded_snippet']}[/cyan]"]

        console.print(Panel("\n".join(body_lines), title=title, expand=False))


if __name__ == "__main__":
    app()
