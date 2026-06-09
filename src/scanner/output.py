import json
import pathlib

from .models import Finding


def to_dict(package: str, source: str, findings: list[Finding]) -> dict:
    return {
        "package": package,
        "source": source,
        "findings": [f.to_dict() for f in findings],
    }


def write_findings(package: str, findings: list[Finding], output_dir: pathlib.Path) -> pathlib.Path:
    data = to_dict(package, "local", findings)
    out = output_dir / f"{package}_findings.json"
    out.write_text(json.dumps(data, indent=2))
    return out


def load_findings(path: pathlib.Path) -> dict:
    return json.loads(path.read_text())
