"""Fleet admin-token bearer gate for zoneedit-mcp (adapted from amt-mcp's amt_gate).

Invariants:

1. The HTTP layer rejects nothing. ``BearerContextMiddleware`` only records whether the presented
   bearer verified; every request reaches the MCP session manager unchanged.
2. The gate lives in the tool-dispatch wrapper (``GatedFastMCP.call_tool``), evaluated per call.
   Every tool call, reads included, needs the bearer.
3. Refusal is an MCP tool error (``ToolError`` -> ``isError: true``), never an HTTP status code.
4. The transport is checked explicitly. Only an explicit ``ZONEEDIT_TRANSPORT=stdio`` skips the
   check; any other value, or none, is treated as HTTP and gated (fail closed).
5. An unresolvable hash (``MCP_ADMIN_TOKEN_HASH`` unset or malformed) refuses every token.

Only the SHA-256 of the token is configured; a presented bearer is hashed and compared with
``hmac.compare_digest``.
"""
from __future__ import annotations

import contextvars
import hashlib
import hmac
import logging
import os
import re
import sys
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ResourceError, ToolError

HASH_ENV = "MCP_ADMIN_TOKEN_HASH"
TRANSPORT_ENV = "ZONEEDIT_TRANSPORT"
TOKEN_NAME = "mcp-admin-token"
FLEET = "fleet"

_HEX64 = re.compile(r"[0-9a-f]{64}")

# One record per call that passed the gate: tool name and principal name, nothing else.
call_log = logging.getLogger("zoneedit_mcp.calls")
# The tool name is client-supplied and is logged before FastMCP validates it, so only a plain
# identifier is written; anything else is replaced.
_LOGGABLE_NAME = re.compile(r"[A-Za-z0-9_.\-]{1,64}")

# True only for the request currently being served, and only when its bearer verified.
# Default False: a process that never installs the middleware (stdio) fails closed.
_bearer_verified: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "zoneedit_bearer_verified", default=False
)
_principal: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "zoneedit_principal", default=None
)


def configured_hash() -> str | None:
    """The configured fleet SHA-256 hex digest, or None when unset or malformed."""
    value = os.environ.get(HASH_ENV, "").strip().lower()
    return value if _HEX64.fullmatch(value) else None


def identify_bearer(presented: str | None) -> str | None:
    """Return FLEET when the presented bearer hashes to the configured digest, else None."""
    fleet = configured_hash()
    if fleet is None or not presented:
        return None
    digest = hashlib.sha256(presented.encode("utf-8")).hexdigest()
    return FLEET if hmac.compare_digest(digest, fleet) else None


def verify_bearer(presented: str | None) -> bool:
    """True only when the presented bearer belongs to the configured fleet principal."""
    return identify_bearer(presented) is not None


def configure_call_log() -> None:
    """Send the per-call record to stderr (stdout is the stdio MCP channel). Idempotent."""
    if not call_log.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(asctime)s %(name)s %(message)s"))
        call_log.addHandler(handler)
    call_log.setLevel(logging.INFO)


def is_stdio_transport() -> bool:
    """Explicit stdio only. Unset or unknown is HTTP, so the gate applies."""
    return os.environ.get(TRANSPORT_ENV, "").strip().lower() == "stdio"


def _bearer_from_scope(scope: dict) -> str | None:
    for key, value in scope.get("headers", []):
        if key.lower() == b"authorization":
            scheme, _, token = value.decode("latin-1").partition(" ")
            if scheme.lower() == "bearer" and token.strip():
                return token.strip()
            return None
    return None


class BearerContextMiddleware:
    """Pure ASGI middleware: records the bearer check result, rejects nothing."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        principal = identify_bearer(_bearer_from_scope(scope))
        reset = _bearer_verified.set(principal is not None)
        reset_principal = _principal.set(principal)
        try:
            await self.app(scope, receive, send)
        finally:
            _principal.reset(reset_principal)
            _bearer_verified.reset(reset)


_REFUSAL = (
    f"this call requires the {TOKEN_NAME} bearer header "
    "(Authorization: Bearer <token>); the call was refused and nothing ran"
)


class GatedFastMCP(FastMCP):
    """FastMCP whose every dispatch (tools, resources and prompts) passes the bearer gate."""

    def _require_bearer(self) -> None:
        # Fail closed: stdio is the only ungated transport, and only when set explicitly.
        if not is_stdio_transport() and not _bearer_verified.get():
            raise ToolError(_REFUSAL)

    async def call_tool(self, name: str, arguments: dict[str, Any]):
        self._require_bearer()
        logged = name if _LOGGABLE_NAME.fullmatch(name) else "<invalid-name>"
        call_log.info("tool=%s principal=%s", logged, _principal.get() or "stdio")
        return await super().call_tool(name, arguments)

    async def read_resource(self, *args: Any, **kwargs: Any):
        if not is_stdio_transport() and not _bearer_verified.get():
            raise ResourceError(_REFUSAL)
        return await super().read_resource(*args, **kwargs)

    async def get_prompt(self, *args: Any, **kwargs: Any):
        # FastMCP surfaces a ValueError from get_prompt as an error result.
        if not is_stdio_transport() and not _bearer_verified.get():
            raise ValueError(_REFUSAL)
        return await super().get_prompt(*args, **kwargs)
