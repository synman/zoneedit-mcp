"""No hard-secret shape and no personal home path in any file of the repository.

A failure names the class, the file and the line. It never prints the matched text. The positive
control runs first: one canary per class, built from fragments, must be detected, and a benign line
must not be, so an emptied pattern list cannot pass as a clean tree.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache"}
SUFFIXES = {".py", ".md", ".html", ".yaml", ".yml", ".toml", ".example", ".json", ".txt", ""}

SHAPES = {
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "aws_access_key_id": re.compile(r"AKIA[0-9A-Z]{16}"),
    "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),
    "sk_style_api_key": re.compile(r"sk-[A-Za-z0-9]{20,}"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."),
    "bearer_literal": re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]{20,}"),
    "personal_home_path": re.compile(r"/Users/[A-Za-z]+"),
    # A TOTP seed or recovery code: a base32 run of 16 or more characters holding a digit 2 to 7.
    # An all-letter run is a name such as an environment variable, so it does not match.
    "totp_seed_shape": re.compile(r"\b(?=[A-Z2-7]*[2-7])[A-Z2-7]{16,}\b"),
}
# Files that hold published TOTP test vectors on purpose (RFC 6238 and a public demo seed). Only the
# seed shape is exempt there; every other shape still applies to them.
SEED_VECTOR_FILES = {"tests/test_totp.py", "tests/test_2fa_tools.py"}


def _canaries() -> dict[str, str]:
    return {
        "private_key": "-----BEGIN " + "RSA PRIVATE KEY-----",
        "aws_access_key_id": "AK" + "IA" + "ABCDEFGHIJKLMNOP",
        "github_token": "gh" + "p_" + "a" * 36,
        "sk_style_api_key": "sk" + "-" + "b" * 24,
        "jwt": "ey" + "J" + "a" * 12 + "." + "b" * 12 + ".sig",
        "bearer_literal": "Bear" + "er " + "c" * 24,
        "personal_home_path": "/Us" + "ers/someone/project",
        "totp_seed_shape": "JBSWY3DP" + "EHPK3PXP",
    }


def _files():
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file() or SKIP_DIRS & set(path.relative_to(ROOT).parts):
            continue
        if path.suffix in SUFFIXES or path.name in {"Dockerfile", ".dockerignore", ".gitignore"}:
            yield path


def test_positive_control_every_shape_is_detected_and_a_benign_line_is_not():
    canaries = _canaries()
    assert set(canaries) == set(SHAPES)
    for name, line in canaries.items():
        assert SHAPES[name].search(line), name
    assert not any(rx.search("def total(rows): return len(rows)") for rx in SHAPES.values())
    assert not SHAPES["totp_seed_shape"].search("PYTHONDONTWRITEBYTECODE=1")


def test_the_scan_sees_the_repository():
    names = {p.name for p in _files()}
    assert {"zoneedit_session.py", "README.md", "Dockerfile", "dns_index.html"} <= names


def test_no_hard_secret_shape_and_no_home_path_in_any_file():
    found = []
    for path in _files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            pytest.fail(f"unreadable as text: {path.relative_to(ROOT)}")
        for number, line in enumerate(text.splitlines(), 1):
            rel = path.relative_to(ROOT).as_posix()
            for name, rx in SHAPES.items():
                if name == "totp_seed_shape" and rel in SEED_VECTOR_FILES:
                    continue
                if rx.search(line):
                    found.append(f"{name} {rel}:{number}")
    assert not found, "; ".join(found)
