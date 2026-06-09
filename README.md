# npm-malware-research

Forensic research tool for analysing malicious npm packages using YARA rules.
Extracts structured threat intelligence from suspicious packages for manual analysis and dataset building.

**Not a CI gate** — depth over speed.

## Install

Requires Python 3.13+.

```bash
pip install -e ".[dev]"
```

## Usage

### Scan a local directory or tarball

```bash
scanner scan path/to/package/
scanner scan path/to/package.tgz
```

### Pretty-print a saved findings file

```bash
scanner report findings.json
```

## Rule layout

```
rules/
  npm/
    binding_gyp.yar    # GYP command expansion (Miasma technique)
    package_json.yar   # lifecycle script abuse
  community/           # drop-in for external rulesets (GuardDog, ReversingLabs)
```

New rules are auto-discovered at runtime — drop a `.yar` file in the right folder.

## Output

Each scan writes `<package>_findings.json`:

```json
{
  "package": "name@version",
  "source": "local",
  "findings": [
    {
      "rule_id": "BindingGyp_NodeExec",
      "severity": "CRITICAL",
      "file": "binding.gyp",
      "line": 7,
      "raw_snippet": "<!(node index.js > /dev/null 2>&1 && echo stub.c)",
      "decoded_snippet": null,
      "source_ref": "https://www.aikido.dev/blog/exploring-binding-gyp-npm-build-system",
      "technique": "GYP command expansion"
    }
  ]
}
```

## Tests

```bash
pytest
```

Fixtures under `tests/fixtures/` are **entirely synthetic** — no real malicious packages are used or downloaded.

## Stack

| Concern | Choice |
|---|---|
| Rule engine | `yara-python` |
| Tarball handling | stdlib `tarfile` |
| CLI | `typer` |
| Tests | `pytest` |
| Output | `rich` (human) + stdlib `json` (machine) |
