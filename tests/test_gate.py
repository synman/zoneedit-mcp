import asyncio
import hashlib

import pytest
from mcp.server.fastmcp.exceptions import ResourceError, ToolError

import zoneedit_gate as g

GOOD = "good-token"
GOOD_HASH = hashlib.sha256(GOOD.encode("utf-8")).hexdigest()


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.delenv(g.TRANSPORT_ENV, raising=False)
    monkeypatch.setenv(g.HASH_ENV, GOOD_HASH)


@pytest.fixture
def verified():
    token = g._bearer_verified.set(True)
    yield
    g._bearer_verified.reset(token)


def test_no_bearer_refused():
    assert g.verify_bearer(None) is False
    assert g.verify_bearer("") is False


def test_wrong_bearer_refused():
    assert g.verify_bearer("not-the-token") is False


def test_unset_hash_refuses_every_token(monkeypatch):
    monkeypatch.delenv(g.HASH_ENV)
    assert g.verify_bearer(GOOD) is False


@pytest.mark.parametrize("value", ["abc", GOOD_HASH[:-1], GOOD_HASH + "0", "z" * 64])
def test_malformed_hash_refuses_every_token(monkeypatch, value):
    monkeypatch.setenv(g.HASH_ENV, value)
    assert g.verify_bearer(GOOD) is False


def test_right_bearer_passes():
    assert g.verify_bearer(GOOD) is True
    assert g.identify_bearer(GOOD) == g.SHARED


def test_right_bearer_passes_gate(verified):
    server = g.GatedFastMCP("t")
    server._require_bearer()


def test_unverified_call_tool_refused():
    server = g.GatedFastMCP("t")
    with pytest.raises(ToolError):
        asyncio.run(server.call_tool("zoneedit_selftest", {}))


def test_unverified_read_resource_refused():
    server = g.GatedFastMCP("t")
    with pytest.raises(ResourceError):
        asyncio.run(server.read_resource("zoneedit://x"))


def test_explicit_stdio_passes_gate(monkeypatch):
    monkeypatch.setenv(g.TRANSPORT_ENV, "stdio")
    g.GatedFastMCP("t")._require_bearer()


def test_unknown_transport_value_is_gated(monkeypatch):
    monkeypatch.setenv(g.TRANSPORT_ENV, "websocket")
    with pytest.raises(ToolError):
        g.GatedFastMCP("t")._require_bearer()


def _run_middleware(header: bytes | None):
    seen = {}

    async def app(scope, receive, send):
        seen["verified"] = g._bearer_verified.get()
        seen["principal"] = g._principal.get()

    headers = [] if header is None else [(b"authorization", header)]
    mw = g.BearerContextMiddleware(app)
    asyncio.run(mw({"type": "http", "headers": headers}, None, None))
    return seen


def test_middleware_records_right_bearer():
    seen = _run_middleware(b"Bearer " + GOOD.encode())
    assert seen == {"verified": True, "principal": g.SHARED}


def test_middleware_records_wrong_or_missing_bearer():
    assert _run_middleware(b"Bearer nope")["verified"] is False
    assert _run_middleware(None)["verified"] is False
