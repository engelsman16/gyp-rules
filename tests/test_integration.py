"""Integration tests for the YARA-based npm malware scanner.

These tests exercise the full scan pipeline (scan -> write_findings ->
load_findings) against the pre-built fixture packages without any mocking or
network access.
"""
import json
import pathlib

import pytest

from scanner.scan import scan
from scanner.output import write_findings, load_findings

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
MALICIOUS = FIXTURES / "malicious"
CLEAN = FIXTURES / "clean"

EXPECTED_RULE_IDS = {
    "BindingGyp_CmdExpansion",
    "BindingGyp_NodeExec",
    "BindingGyp_PythonExec",
    "BindingGyp_PymodExpansion",
    "BindingGyp_ShellExec",
    "BindingGyp_NetworkFetch",
    "BindingGyp_StdoutSuppress",
    "BindingGyp_TypeNoneCombo",
    "BindingGyp_FileWriteExpansion",
    "PkgJson_LifecycleScript",
    "PkgJson_ObfuscatedScript",
    "PkgJson_NetworkInScript",
}


def test_full_scan_malicious_finds_all_rules(tmp_path):
    """Scanning the malicious fixture directory must fire every expected rule."""
    _label, findings = scan(str(MALICIOUS))
    found_ids = {f.rule_id for f in findings}
    assert EXPECTED_RULE_IDS == found_ids, (
        f"Missing rules: {EXPECTED_RULE_IDS - found_ids}; "
        f"Unexpected rules: {found_ids - EXPECTED_RULE_IDS}"
    )


def test_full_scan_malicious_decoded_snippet(tmp_path):
    """At least one finding must have decoded_snippet == 'hello' (from aGVsbG8=)."""
    _label, findings = scan(str(MALICIOUS))
    decoded_values = [f.decoded_snippet for f in findings if f.decoded_snippet is not None]
    assert any(v == "hello" for v in decoded_values), (
        f"No finding with decoded_snippet='hello'. Decoded values found: {decoded_values}"
    )


def test_full_scan_source_is_local(tmp_path):
    """write_findings must record source='local' in the JSON output."""
    label, findings = scan(str(MALICIOUS))
    out_path = write_findings(label, findings, tmp_path)
    data = load_findings(out_path)
    assert data["source"] == "local", (
        f"Expected source='local', got source='{data['source']}'"
    )


def test_full_scan_clean_no_findings(tmp_path):
    """Scanning the clean fixture directory must produce zero findings."""
    _label, findings = scan(str(CLEAN))
    assert findings == [], (
        f"Expected no findings on clean fixture, got {len(findings)}: "
        + ", ".join(f.rule_id for f in findings)
    )
