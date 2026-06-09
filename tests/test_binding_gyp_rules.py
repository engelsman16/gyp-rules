"""Unit tests for rules/npm/binding_gyp.yar.

One positive test (malicious fixture fires the rule) and one negative test
(clean fixture does not fire the rule) per rule — 18 tests total.
"""
import pathlib

import pytest
import yara

RULES = yara.compile(
    str(pathlib.Path(__file__).parent.parent / "rules/npm/binding_gyp.yar")
)
MALICIOUS = pathlib.Path(__file__).parent / "fixtures/malicious/binding.gyp"
CLEAN = pathlib.Path(__file__).parent / "fixtures/clean/binding.gyp"


def _fire(rule_id: str, path: pathlib.Path) -> bool:
    matches = RULES.match(filepath=str(path))
    return any(m.rule == rule_id for m in matches)


# ── BindingGyp_CmdExpansion ────────────────────────────────────────────────

def test_BindingGyp_CmdExpansion_fires():
    assert _fire("BindingGyp_CmdExpansion", MALICIOUS)


def test_BindingGyp_CmdExpansion_clean():
    assert not _fire("BindingGyp_CmdExpansion", CLEAN)


# ── BindingGyp_NodeExec ────────────────────────────────────────────────────

def test_BindingGyp_NodeExec_fires():
    assert _fire("BindingGyp_NodeExec", MALICIOUS)


def test_BindingGyp_NodeExec_clean():
    assert not _fire("BindingGyp_NodeExec", CLEAN)


# ── BindingGyp_PythonExec ──────────────────────────────────────────────────

def test_BindingGyp_PythonExec_fires():
    assert _fire("BindingGyp_PythonExec", MALICIOUS)


def test_BindingGyp_PythonExec_clean():
    assert not _fire("BindingGyp_PythonExec", CLEAN)


# ── BindingGyp_PymodExpansion ──────────────────────────────────────────────

def test_BindingGyp_PymodExpansion_fires():
    assert _fire("BindingGyp_PymodExpansion", MALICIOUS)


def test_BindingGyp_PymodExpansion_clean():
    assert not _fire("BindingGyp_PymodExpansion", CLEAN)


# ── BindingGyp_ShellExec ───────────────────────────────────────────────────

def test_BindingGyp_ShellExec_fires():
    assert _fire("BindingGyp_ShellExec", MALICIOUS)


def test_BindingGyp_ShellExec_clean():
    assert not _fire("BindingGyp_ShellExec", CLEAN)


# ── BindingGyp_NetworkFetch ────────────────────────────────────────────────

def test_BindingGyp_NetworkFetch_fires():
    assert _fire("BindingGyp_NetworkFetch", MALICIOUS)


def test_BindingGyp_NetworkFetch_clean():
    assert not _fire("BindingGyp_NetworkFetch", CLEAN)


# ── BindingGyp_StdoutSuppress ──────────────────────────────────────────────

def test_BindingGyp_StdoutSuppress_fires():
    assert _fire("BindingGyp_StdoutSuppress", MALICIOUS)


def test_BindingGyp_StdoutSuppress_clean():
    assert not _fire("BindingGyp_StdoutSuppress", CLEAN)


# ── BindingGyp_TypeNoneCombo ───────────────────────────────────────────────

def test_BindingGyp_TypeNoneCombo_fires():
    assert _fire("BindingGyp_TypeNoneCombo", MALICIOUS)


def test_BindingGyp_TypeNoneCombo_clean():
    assert not _fire("BindingGyp_TypeNoneCombo", CLEAN)


# ── BindingGyp_FileWriteExpansion ──────────────────────────────────────────

def test_BindingGyp_FileWriteExpansion_fires():
    assert _fire("BindingGyp_FileWriteExpansion", MALICIOUS)


def test_BindingGyp_FileWriteExpansion_clean():
    assert not _fire("BindingGyp_FileWriteExpansion", CLEAN)
