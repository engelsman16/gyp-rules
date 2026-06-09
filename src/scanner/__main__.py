import typer

app = typer.Typer(help="npm malware research scanner")


@app.command()
def scan(path: str) -> None:
    """Scan a local directory or .tgz tarball for malicious patterns."""
    raise NotImplementedError("scan not yet implemented")


@app.command()
def report(findings: str) -> None:
    """Pretty-print a saved findings JSON file."""
    raise NotImplementedError("report not yet implemented")


if __name__ == "__main__":
    app()
