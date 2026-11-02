"""Conformity check on the tool list a client receives (list_tools), not the decorators.

Shape rules: mcp-builder SKILL.md 3.3 and qvc_conventions.md (Tool annotations, Write guards,
Tool docstrings, Server instructions). The write-guard parameter is ``confirmed``.
"""
import asyncio
import re

import zoneedit_server as srv

EXPECTED_TOOLS = 9
GUARD = "confirmed"
WRITE_TOOLS = {"zoneedit_record_add", "zoneedit_record_update", "zoneedit_record_delete",
               "zoneedit_2fa_latch_clear"}
READ_TOOLS = {"zoneedit_records", "zoneedit_selftest", "zoneedit_2fa_status", "zoneedit_domains",
              "zoneedit_schema"}
# Explicit declarations captured from the server before the conformity pass. Never changed.
PRIOR = {
    "zoneedit_records": ("ZoneEdit Records", True),
    "zoneedit_selftest": ("ZoneEdit Self-Test", True),
    "zoneedit_record_add": ("ZoneEdit Add Record", False),
    "zoneedit_record_update": ("ZoneEdit Update Record", False),
    "zoneedit_record_delete": ("ZoneEdit Delete Record", False),
    "zoneedit_2fa_status": ("ZoneEdit 2FA Status", True),
    "zoneedit_2fa_latch_clear": ("ZoneEdit Clear Login Latch", False),
}
MAX_CHARS = 2048
PROPERTY_NAME = re.compile(r"[A-Za-z0-9_.-]{1,64}")
MISSING_SPACE = re.compile(r"[a-z]\.[A-Z]")


def _tools():
    return {tool.name: tool for tool in asyncio.run(srv.mcp.list_tools())}


def _ann(tool, key):
    annotations = tool.annotations
    if annotations is None:
        return None
    if isinstance(annotations, dict):
        return annotations.get(key)
    return getattr(annotations, key, None)


def _props(tool):
    return (tool.inputSchema or {}).get("properties", {})


def test_exactly_nine_tools_are_listed():
    tools = _tools()
    assert len(tools) == EXPECTED_TOOLS
    assert set(tools) == READ_TOOLS | WRITE_TOOLS


def test_every_tool_declares_title_and_read_only_hint():
    for name, tool in _tools().items():
        assert _ann(tool, "title"), name
        assert _ann(tool, "readOnlyHint") is not None, name


def test_explicit_declarations_are_unchanged():
    tools = _tools()
    for name, (title, read_only) in PRIOR.items():
        assert _ann(tools[name], "title") == title, name
        assert _ann(tools[name], "readOnlyHint") is read_only, name


def test_guarded_tools_are_writes_and_unguarded_tools_are_reads():
    tools = _tools()
    guarded = {name for name, tool in tools.items() if GUARD in _props(tool)}
    unguarded = set(tools) - guarded
    assert guarded == WRITE_TOOLS
    assert unguarded == READ_TOOLS
    for name in guarded:
        assert _ann(tools[name], "readOnlyHint") is False, name
    for name in unguarded:
        assert _ann(tools[name], "readOnlyHint") is True, name


def test_every_description_is_within_the_cap():
    for name, tool in _tools().items():
        assert len(tool.description or "") <= MAX_CHARS, name


def test_every_input_property_has_a_schema_description():
    for name, tool in _tools().items():
        for prop, schema in _props(tool).items():
            assert isinstance(schema.get("description"), str), f"{name}.{prop}"
            assert schema["description"].strip(), f"{name}.{prop}"


def test_every_property_name_is_a_legal_name():
    for name, tool in _tools().items():
        for prop in _props(tool):
            assert PROPERTY_NAME.fullmatch(prop), f"{name}.{prop}"


def test_server_instructions_are_within_the_cap_and_have_no_missing_space():
    text = srv.mcp.instructions or ""
    assert text
    assert len(text) <= MAX_CHARS
    assert not MISSING_SPACE.search(text)


def test_write_guard_line_is_on_write_tools_only():
    for name, tool in _tools().items():
        description = tool.description or ""
        if name in WRITE_TOOLS:
            assert "WRITE GUARD:" in description, name
        else:
            assert "WRITE GUARD:" not in description, name


def test_every_description_has_when_and_returns_and_no_args_section():
    for name, tool in _tools().items():
        description = tool.description or ""
        assert "WHEN to use:" in description, name
        assert "Returns:" in description, name
        assert "Args:" not in description, name
