"""Unit tests for rules/npm/package_json.yar.

One positive test (malicious fixture fires the rule) and one negative test
(clean fixture does not fire the rule) per rule — 6 tests total.
"""
import pathlib

import pytest
import yara

RULES = yara.compile(
    str(pathlib.Path(__file__).parent.parent / "rules/npm/package_json.yar")
)
MALICIOUS = pathlib.Path(__file__).parent / "fixtures/malicious/package.json"
CLEAN = pathlib.Path(__file__).parent / "fixtures/clean/package.json"


def _fire(rule_id: str, path: pathlib.Path) -> bool:
    matches = RULES.match(filepath=str(path))
    return any(m.rule == rule_id for m in matches)


# ── PkgJson_LifecycleScript ────────────────────────────────────────────────

def test_PkgJson_LifecycleScript_fires():
    assert _fire("PkgJson_LifecycleScript", MALICIOUS)


def test_PkgJson_LifecycleScript_clean():
    assert not _fire("PkgJson_LifecycleScript", CLEAN)


# ── PkgJson_ObfuscatedScript ───────────────────────────────────────────────

def test_PkgJson_ObfuscatedScript_fires():
    assert _fire("PkgJson_ObfuscatedScript", MALICIOUS)


def test_PkgJson_ObfuscatedScript_clean():
    assert not _fire("PkgJson_ObfuscatedScript", CLEAN)


# ── PkgJson_NetworkInScript ────────────────────────────────────────────────

def test_PkgJson_NetworkInScript_fires():
    assert _fire("PkgJson_NetworkInScript", MALICIOUS)


def test_PkgJson_NetworkInScript_clean():
    assert not _fire("PkgJson_NetworkInScript", CLEAN)
