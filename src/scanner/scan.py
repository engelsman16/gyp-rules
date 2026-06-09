import pathlib
import tarfile
import tempfile

from .decode import try_decode
from .models import Finding
from .rules import rules_for_file


def _offset_to_line(content: bytes, offset: int) -> int:
    return content[:offset].count(b"\n") + 1


def _snippet(lines: list[str], line_no: int, context: int = 3) -> str:
    start = max(0, line_no - 1 - context)
    end = min(len(lines), line_no + context)
    return "\n".join(lines[start:end])


def scan_file(path: pathlib.Path, package_root: pathlib.Path) -> list[Finding]:
    filename = path.name
    applicable = rules_for_file(filename)
    if not applicable:
        return []

    content = path.read_bytes()
    lines = content.decode("utf-8", errors="replace").splitlines()
    findings: list[Finding] = []

    for ruleset in applicable:
        for match in ruleset.match(data=content):
            meta = match.meta
            # Lowest offset among all matched strings for line resolution.
            # yara-python 4.x: match.strings is a list of StringMatch objects;
            # each has .instances with .offset attributes.
            offsets = [
                inst.offset
                for s in match.strings
                for inst in s.instances
            ] if match.strings else [0]
            line_no = _offset_to_line(content, offsets[0]) if offsets else 1
            snippet = _snippet(lines, line_no)
            findings.append(Finding(
                rule_id=match.rule,
                severity=meta.get("severity", "UNKNOWN"),
                file=str(path.relative_to(package_root)),
                line=line_no,
                raw_snippet=snippet,
                decoded_snippet=try_decode(snippet),
                source_ref=meta.get("source_ref", ""),
                technique=meta.get("technique", ""),
            ))

    return findings


def scan_directory(root: pathlib.Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in sorted(root.rglob("*")):
        if path.is_file():
            findings.extend(scan_file(path, root))
    return findings


def scan_tarball(tarball: pathlib.Path) -> list[Finding]:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = pathlib.Path(tmp)
        with tarfile.open(tarball, "r:gz") as tf:
            tf.extractall(tmp_path, filter="data")
        return scan_directory(tmp_path)


def scan(target: str) -> tuple[str, list[Finding]]:
    """
    Scan a local directory or .tgz tarball.

    Returns (package_label, findings).
    """
    path = pathlib.Path(target).expanduser().resolve()
    if path.is_dir():
        findings = scan_directory(path)
        label = path.name
    elif path.suffix in (".gz", ".tgz") or target.endswith(".tar.gz"):
        findings = scan_tarball(path)
        label = path.stem.replace(".tar", "")
    else:
        raise ValueError(f"Target must be a directory or .tgz tarball: {target}")

    # TODO(registry): fetch from npm registry
    # Caution: introduces network dep, rate limits, and risk of inadvertently
    # pulling and partially executing untrusted tarballs. Needs sandboxing
    # design before implementing. Must NEVER run install or build steps on
    # fetched packages.
    # raise NotImplementedError("registry fetch not yet implemented")

    return label, findings
