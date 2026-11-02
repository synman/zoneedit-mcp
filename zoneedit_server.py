#!/usr/bin/env python3
"""zoneedit-mcp: read-only ZoneEdit DNS records (streamable HTTP, bearer-gated).

Configuration (environment, none secret):
    MCP_ADMIN_TOKEN_HASH   SHA-256 hex of the fleet mcp-admin-token. Required over HTTP.
    ZONEEDIT_TRANSPORT     ``http`` (default) or ``stdio``; set by ``main`` from --transport.
    ZONEEDIT_BIND_HOST     bind address, default 127.0.0.1.
    ZONEEDIT_PORT          bind port, default 8768.
    ZONEEDIT_ALLOWED_HOSTS comma-separated extra Host names accepted behind an ingress.
    ZONEEDIT_SECRETS_CLI   the vault CLI (secrets.py) used to read the panel credentials.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
from typing import Annotated

from mcp.server.fastmcp.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import Field

import zoneedit_session
import zoneedit_tools
from zoneedit_gate import (
    HASH_ENV,
    TRANSPORT_ENV,
    BearerContextMiddleware,
    GatedFastMCP,
    configure_call_log,
    configured_hash,
    is_stdio_transport,
)

# This app's version-of-record, semver, bumped by hand with every change to a serving module
# (hooks/version_bump_gate.py enforces the bump). FastMCP takes no version= kwarg; the lowlevel
# Server's version is what initialize reports, so build_server sets it. Never derive it from a
# library or package metadata.
__version__ = "1.9.1"

DEFAULT_BIND_HOST = "127.0.0.1"
DEFAULT_PORT = 8768

INSTRUCTIONS = (
    "Over HTTP every tool call needs the fleet mcp-admin-token bearer; a tool call without it is "
    "refused as a tool error and nothing runs. "
    "Use these tools to list and change the public DNS records of a domain of the ZoneEdit account "
    "in the ZoneEdit control panel; search for them when a task asks to read, add, change or remove "
    "a DNS record. "
    "Tools: zoneedit_records reads the records (optional host filter, @ for the apex, with "
    "coverage fields). zoneedit_selftest checks that the login and DNS page work and returns no "
    "records. zoneedit_record_add adds one record. zoneedit_record_update changes one row matched "
    "by its exact current content or hash. zoneedit_record_delete deletes one row matched the same way. "
    "Learn each record type's form fields and select values with zoneedit_schema before a write; "
    "the write tools take them in fields. "
    "The three write tools preview unless confirmed=true, never replace a record, and are "
    "verified by a panel re-read. "
    "Every record tool takes an optional domain (see zoneedit_domains). Empty means the account's "
    "only domain; with several domains the call is refused (domain_required) and lists them. "
    "Two second-factor tools: zoneedit_2fa_status reads the login state without logging in; "
    "zoneedit_2fa_latch_clear clears the login latch and previews unless confirmed=true. "
    "Discovery tools: zoneedit_domains lists the account's domains; zoneedit_schema reads one "
    "domain's record types, form fields, TTL options and editor settings. "
    "Credentials are read from the vault in-process and are never a tool argument or a returned "
    "value."
)


def build_server() -> GatedFastMCP:
    """Construct a fresh gated, stateless FastMCP with no tools registered."""
    server = GatedFastMCP("zoneedit-mcp", instructions=INSTRUCTIONS, stateless_http=True)
    server._mcp_server.version = __version__
    return server


async def zoneedit_records(
    host: Annotated[str, Field(description=(
        "Only return records whose host equals this exactly (lowercase bare label such as www, "
        "or @ for the apex). Empty returns every record of the zone."))] = "",
    domain: Annotated[str, Field(description=(
        "Domain name of the account, such as example.net, read from zoneedit_domains. Empty is "
        "allowed only when the account holds exactly one domain; with several it is refused "
        "(domain_required)."))] = "",
) -> dict:
    """Read every DNS record of one domain of the ZoneEdit account, optionally one host only.

    WHEN to use: first stop to see which records exist, or to check one host before a change.
    Read-only: it never changes the zone. Empty ``domain`` means the account's only domain; with
    several domains the call is refused (domain_required) and lists them, so name one from
    zoneedit_domains.

    Sibling disambiguation: ``zoneedit_records`` reads the records; ``zoneedit_selftest`` only
    checks that the login and DNS page work and returns no records.

    Returns: ``{records: [{type, host, content, ttl, hash, pending}], read, panel_total,
    pages_read, pages_expected, complete, filter, matched}``, plus ``warning`` when the read is
    incomplete or empty; zero records read is not proof the zone has none. ``pending: true``
    marks a row the panel shows as queued, queued for deletion or revoked, which is not
    published. The result carries ``domain``, the domain read. A refused domain returns
    ``{ok: false, refused: bad_domain | domain_required | unknown_domain}``, and the last two list
    the account's ``domains``. A failed browser step raises a tool error.
    """
    try:
        return await asyncio.to_thread(zoneedit_tools.records, host, domain,
                                       runner=zoneedit_session.run)
    except Exception as ex:
        raise ToolError(f"zoneedit_records failed: {zoneedit_tools.safe_error(ex)}") from None


async def zoneedit_domains() -> dict:
    """List the domains of the ZoneEdit account and the one the editor shows by default.

    WHEN to use: before zoneedit_schema or zoneedit_records with a domain, to learn the exact names
    the account holds. Read-only: it never changes the account or any zone.

    Sibling disambiguation: ``zoneedit_domains`` lists domain names only; ``zoneedit_schema`` reads
    the record types of one domain.

    Returns: ``{domains: [name], default: name only when the account has exactly one domain, else null,
    count, total, complete}``. ``total`` is the account's own count and ``complete`` is true only when
    every listed domain was read. A failed browser step raises a tool error.
    """
    try:
        return await asyncio.to_thread(zoneedit_tools.domains, runner=zoneedit_session.run)
    except Exception as ex:
        raise ToolError(f"zoneedit_domains failed: {zoneedit_tools.safe_error(ex)}") from None


async def zoneedit_schema(
    domain: Annotated[str, Field(description=(
        "Domain name of the account, such as example.net, read from zoneedit_domains. Empty is "
        "allowed only when the account holds exactly one domain; with several it is refused "
        "(domain_required)."))] = "",
    record_type: Annotated[str, Field(description=(
        "Optional record type name such as CAA or MX (compared uppercased). Empty reads every type "
        "the add form offers."))] = "",
) -> dict:
    """Read the record types of one domain: each type's form fields (name, label, kind, required,
    disabled, placeholder, select options), the TTL labels and the editor's settings.

    WHEN to use: before adding or changing a record, to learn which fields a type takes and which
    values its selects accept. Read-only: it selects types and reads the form; it never submits,
    saves or deletes anything, and it never reads a text value.

    Sibling disambiguation: ``zoneedit_schema`` describes the form; ``zoneedit_domains`` lists the
    domain names; ``zoneedit_record_add`` writes a record.

    Returns: ``{domain, type_names, types: {TYPE: {fields: [...]}}, ttl_options, settings,
    type_count, unsettled, complete}``. A type that did not settle is listed in ``unsettled`` with no
    fields; ``complete`` is false then. Refusals return ``{ok: false, refused}`` with ``bad_domain``,
    ``domain_required`` (plus ``domains``: the account holds several and none was named),
    ``unknown_domain`` (plus ``domains``) or ``unknown_record_type`` (plus ``types``). A failed
    browser step raises a tool error.
    """
    try:
        return await asyncio.to_thread(zoneedit_tools.schema, domain, record_type,
                                       runner=zoneedit_session.run)
    except Exception as ex:
        raise ToolError(f"zoneedit_schema failed: {zoneedit_tools.safe_error(ex)}") from None


async def zoneedit_selftest(
    domain: Annotated[str, Field(description=(
        "Domain name of the account, such as example.net, read from zoneedit_domains. Empty opens the "
        "account's only domain, or with several the first listed one; the result names the domain used."))] = "",
) -> dict:
    """Check that the ZoneEdit panel login and DNS page work, without returning any record.

    WHEN to use: after a credential change or a deploy, or when zoneedit_records fails, to tell
    a login problem from a page problem. Read-only and changes nothing.

    Sibling disambiguation: ``zoneedit_selftest`` returns no records; ``zoneedit_records`` reads
    the records.

    Returns: on success ``{login: "ok", domain, dns_page, panel_total, pages, bulk_save_off,
    second_factor, seed}``, where ``domain`` is the domain opened, ``second_factor`` is ``answered``,
    ``not_asked`` or ``unknown`` and ``seed`` is ``present`` or ``absent`` only after an answered code
    page, else ``not_read``. A bad ``domain`` returns ``{ok: false, refused: bad_domain}``. A failed
    login, a rejected second factor (``second_factor_rejected``), a latch after a recent failure
    (``login_latched``), a missing seed (``second_factor_required``) or any other failure returns
    ``{ok: false, error_type}`` and does not raise; ``error_type`` is a name, never a message.
    ``zoneedit_records`` and the write tools raise a tool error instead.
    """
    return await asyncio.to_thread(zoneedit_tools.selftest, domain, runner=zoneedit_session.run)


async def zoneedit_2fa_status() -> dict:
    """Report the ZoneEdit second-factor state without logging in: the last login's outcome, the login
    latch and whether the vault holds a usable seed.

    WHEN to use: before a login or after zoneedit_selftest fails, to see whether a login latch is set
    and whether the seed is present. Read-only: it never logs in, never opens a browser and never
    returns the seed or a code.

    Sibling disambiguation: ``zoneedit_2fa_status`` reads the state only; ``zoneedit_2fa_latch_clear``
    clears the latch.

    Returns: ``{seed: present|absent|invalid, last_second_factor: answered|not_asked|null,
    latch_seconds_left, last_submitted_step, step_seconds_left, epoch}``. ``seed`` is a name, never
    the value. A failed read raises a tool error.
    """
    try:
        return await asyncio.to_thread(zoneedit_tools.twofa_status)
    except Exception as ex:
        raise ToolError(f"zoneedit_2fa_status failed: {zoneedit_tools.safe_error(ex)}") from None


async def zoneedit_2fa_latch_clear(
    confirmed: Annotated[bool, Field(description=(
        "False previews the seconds left and changes nothing. True, only after the operator approves "
        "clearing the login latch, lets the next login run at once."))] = False,
) -> dict:
    """Clear the ZoneEdit login latch so the next login may run. Previews unless confirmed is True.

    WHEN to use: a login failed or a second-factor code was rejected, so the 900 s latch blocks every
    new login. Clear it only after the cause is checked.

    WRITE GUARD: with ``confirmed`` True the latch is cleared and the next login runs without waiting.
    With ``confirmed`` unset the tool changes nothing and reports the seconds left; it does not log in.

    Sibling disambiguation: ``zoneedit_2fa_latch_clear`` only clears the latch; ``zoneedit_2fa_status``
    reads it.

    Returns: a preview ``{ok: true, confirmed: false, latch_seconds_left, action: "clear_latch"}``, or
    ``{ok: true, confirmed: true, cleared_seconds, action: "clear_latch"}`` once confirmed. A failed
    step raises a tool error.
    """
    try:
        return await asyncio.to_thread(zoneedit_tools.twofa_latch_clear, confirmed)
    except Exception as ex:
        raise ToolError(f"zoneedit_2fa_latch_clear failed: {zoneedit_tools.safe_error(ex)}") from None


FIELDS_DESCRIPTION = (
    "Optional form fields by name, each value a string. Names come from zoneedit_schema for this record "
    "type (for example a CAA tag, or an SRV service). A select takes an option's text or the part before "
    "\" - \"; a checkbox takes true or false. host, type and ttl are never names here. Empty leaves the "
    "other fields as the panel shows them.")


async def zoneedit_record_add(
    type: Annotated[str, Field(description=(
        "Record type as zoneedit_schema lists it (matched without case). Any type the form offers. "
        "The apex A, NS and SOA answer for the whole zone and DYN rows are kept fresh by update "
        "clients, so preview those first."))],
    host: Annotated[str, Field(description=(
        "Bare host label inside the domain, such as www, or @ for the apex. Never the domain's own "
        "name, nor a name ending in .<domain>."))],
    content: Annotated[str, Field(description=(
        "Record value as the panel shows it, the legacy input. CAA: three space-separated parts, flag tag "
        "provider. MX and CNAME: a trailing dot is added when missing. Empty when the record uses fields."))] = "",
    ttl: Annotated[str, Field(description=(
        "Optional panel TTL label such as \"1 hour\". Empty leaves the panel default."))] = "",
    prio: Annotated[str, Field(description=(
        "MX priority, digits only. Required for MX (bad_prio otherwise) and refused for types without a "
        "priority field."))] = "",
    confirmed: Annotated[bool, Field(description=(
        "False previews and changes nothing. True, only after the operator approves this exact "
        "record, adds it to the live zone."))] = False,
    domain: Annotated[str, Field(description=(
        "Domain name of the account, such as example.net, read from zoneedit_domains. Empty is "
        "allowed only when the account holds exactly one domain; with several it is refused "
        "(domain_required)."))] = "",
    fields: Annotated[dict[str, str] | None, Field(description=FIELDS_DESCRIPTION)] = None,
) -> dict:
    """Add one DNS record to one domain of the ZoneEdit account. Previews unless confirmed is True.

    WHEN to use: create a new row, including a further row of a type the host already has (a second
    MX or TXT). To change a row that exists, use ``zoneedit_record_update``. Call ``zoneedit_schema`` first to learn the
    type's form fields and the values its selects accept.

    WRITE GUARD: with ``confirmed`` True the record is added to the live zone and reaches the
    internet after DNS propagation. With ``confirmed`` unset the tool saves nothing and returns
    a preview of ``before``, ``after`` and ``values``; it still logs in and reads the panel. The apex A,
    NS, SOA and DYN rows steer the zone or belong to update clients: preview them, confirm only on
    the operator's word.

    Sibling disambiguation: ``zoneedit_record_add`` only creates and stops at a panel
    replace prompt. ``zoneedit_record_update`` changes one row you name by its exact content.

    Returns: a preview ``{ok: true, confirmed: false, action, domain, before, after, values}``. A
    refusal ``{ok: false, refused: <code>}``; codes include bad_domain, domain_required and
    unknown_domain (with ``domains``), bad_type, bad_host,
    schema_unavailable, bad_field, unknown_field, field_disabled, bad_option, missing_field (with
    ``missing``), empty_content, bad_caa, bad_prio, bad_ttl, cname_conflict, incomplete_read
    and bulk_save_on_or_unknown. A confirmed write returns ``{ok, confirmed: true, action, domain,
    before, after, values, panel_verified, verified}``, with ``differences`` when the panel re-read
    disagrees. ``dns_readback`` and ``dns_matches`` are informative only and appear after a verified
    write. A replace prompt returns ``refused: replace_prompt_shown`` and nothing is confirmed. A
    failure after the final Save returns ``{ok: false, outcome: "unknown", message}``: read the zone
    before any retry. A browser step failure raises a tool error.
    """
    try:
        return await asyncio.to_thread(zoneedit_tools.record_add, type, host, content, ttl, prio,
                                       confirmed, domain=domain, fields=fields,
                                       runner=zoneedit_session.run)
    except Exception as ex:
        raise ToolError(f"zoneedit_record_add failed: {zoneedit_tools.safe_error(ex)}") from None


async def zoneedit_record_update(
    type: Annotated[str, Field(description=(
        "Record type of the row to change, as zoneedit_schema lists it. Any type. NS and SOA steer the "
        "whole zone, the apex A answers for the bare domain and DYN rows are kept fresh by update "
        "clients, so preview those first."))],
    host: Annotated[str, Field(description=(
        "Bare host label inside the domain, such as www, or @ for the apex."))],
    expect_content: Annotated[str, Field(description=(
        "The row's current content exactly as the panel shows it. Matched exactly, with no "
        "normalising and no wildcard; a mismatch is refused (content_mismatch) and two identical "
        "rows are refused (ambiguous). Empty when expect_hash names the row."))] = "",
    new_content: Annotated[str, Field(description=(
        "Replacement content in the same format as zoneedit_record_add content. Empty keeps the "
        "row's content (use fields for other form fields)."))] = "",
    new_ttl: Annotated[str, Field(description=(
        "Optional new TTL label such as \"1 hour\". Empty keeps the row's current TTL."))] = "",
    new_prio: Annotated[str, Field(description=(
        "Optional new MX priority, digits only. Allowed for types with a priority field."))] = "",
    confirmed: Annotated[bool, Field(description=(
        "False previews and changes nothing. True, only after the operator approves this exact "
        "row change, edits the one matched row in the live zone."))] = False,
    domain: Annotated[str, Field(description=(
        "Domain name of the account, such as example.net, read from zoneedit_domains. Empty is "
        "allowed only when the account holds exactly one domain; with several it is refused "
        "(domain_required)."))] = "",
    expect_hash: Annotated[str, Field(description=(
        "Optional row hash from zoneedit_records, matched exactly. Given with expect_content, the same "
        "row must satisfy both."))] = "",
    fields: Annotated[dict[str, str] | None, Field(description=FIELDS_DESCRIPTION)] = None,
) -> dict:
    """Change one DNS record of one domain of the ZoneEdit account, matched by type, host and exact
    current content or hash. Previews unless confirmed is True.

    WHEN to use: edit the value, TTL or other fields of a record that exists. To create a new record
    use ``zoneedit_record_add``. Call ``zoneedit_schema`` first to learn the type's form fields.

    WRITE GUARD: with ``confirmed`` True the matched row is rewritten in the live zone and the new
    value reaches the internet after DNS propagation. With ``confirmed`` unset the tool saves
    nothing and returns a preview of ``before``, ``after`` and ``values``; it still logs in and reads
    the panel. The apex A, NS, SOA and DYN rows steer the zone or belong to update clients: preview
    them, confirm only on the operator's word.

    Sibling disambiguation: ``zoneedit_record_update`` edits one row in place, selected by exact
    ``expect_content`` or ``expect_hash``. ``zoneedit_record_add`` creates a row beside the
    others; ``zoneedit_record_delete`` removes the row instead of rewriting it.

    Returns: a preview ``{ok: true, confirmed: false, action: "update", domain, before, after, values}``.
    A refusal ``{ok: false, refused: <code>}``; codes include bad_domain, domain_required and
    unknown_domain (with ``domains``), bad_type, bad_hash, schema_unavailable,
    bad_field, unknown_field, field_disabled, bad_option, bad_ttl, not_found, content_mismatch,
    ambiguous, empty_content, no_change, incomplete_read and bulk_save_on_or_unknown. A confirmed
    write returns ``{ok, confirmed: true, action, domain, before, after, values, panel_verified,
    verified}``, with ``differences`` when the panel re-read disagrees; ``dns_readback`` and
    ``dns_matches`` are informative only. A replace prompt returns ``refused: replace_prompt_shown``.
    A failure after the final Save returns ``{ok: false, outcome: "unknown", message}``: read the zone
    before any retry. A browser step failure raises a tool error.
    """
    try:
        return await asyncio.to_thread(zoneedit_tools.record_update, type, host, expect_content,
                                       new_content, new_ttl, new_prio, confirmed,
                                       domain=domain, expect_hash=expect_hash, fields=fields,
                                       runner=zoneedit_session.run)
    except Exception as ex:
        raise ToolError(f"zoneedit_record_update failed: {zoneedit_tools.safe_error(ex)}") from None


async def zoneedit_record_delete(
    type: Annotated[str, Field(description=(
        "Record type of the row to delete, as zoneedit_schema lists it. Any type. Deleting an NS or SOA "
        "row, or the apex A, can take the whole zone offline and a DYN row is kept fresh by update "
        "clients, so preview those first."))],
    host: Annotated[str, Field(description=(
        "Bare host label inside the domain, such as www, or @ for the apex."))],
    expect_content: Annotated[str, Field(description=(
        "The row's current content exactly as the panel shows it. Matched exactly, with no "
        "normalising and no wildcard; a mismatch is refused (content_mismatch) and two identical "
        "rows are refused (ambiguous). Empty when expect_hash names the row."))] = "",
    confirmed: Annotated[bool, Field(description=(
        "False previews and changes nothing. True, only after the operator approves this exact "
        "row, deletes the one matched row from the live zone."))] = False,
    domain: Annotated[str, Field(description=(
        "Domain name of the account, such as example.net, read from zoneedit_domains. Empty is "
        "allowed only when the account holds exactly one domain; with several it is refused "
        "(domain_required)."))] = "",
    expect_hash: Annotated[str, Field(description=(
        "Optional row hash from zoneedit_records, matched exactly. Given with expect_content, the same "
        "row must satisfy both."))] = "",
) -> dict:
    """Delete one DNS record of one domain of the ZoneEdit account, matched by type, host and exact
    current content or hash. Previews unless confirmed is True.

    WHEN to use: retire a record that exists and is no longer wanted. To change a record in
    place use ``zoneedit_record_update``.

    WRITE GUARD: with ``confirmed`` True the matched row is deleted from the live zone and stops
    answering after DNS propagation. With ``confirmed`` unset the tool clicks nothing and returns
    a preview of ``before``; it still logs in and reads the panel. The apex A, NS, SOA and DYN rows
    steer the zone or belong to update clients: preview them, confirm only on the operator's word.

    Sibling disambiguation: ``zoneedit_record_delete`` removes the row. ``zoneedit_record_update``
    rewrites it in place; ``zoneedit_record_add`` only creates.

    Returns: a preview ``{ok: true, confirmed: false, action: "delete", domain, before, after: null}``.
    A refusal ``{ok: false, refused: <code>}``; codes include bad_domain, domain_required and
    unknown_domain (with ``domains``), bad_type, bad_hash, not_found,
    content_mismatch, ambiguous, empty_content, incomplete_read and bulk_save_on_or_unknown. A
    confirmed delete returns ``{ok, confirmed: true, action, domain, before, after: null,
    panel_verified, verified}``, with ``differences`` when the panel re-read disagrees;
    ``dns_readback`` and ``dns_matches`` are informative only. A replace prompt returns
    ``refused: replace_prompt_shown``. A failure after the final Delete returns
    ``{ok: false, outcome: "unknown", message}``: read the zone before any retry. A browser step
    failure raises a tool error.
    """
    try:
        return await asyncio.to_thread(zoneedit_tools.record_delete, type, host, expect_content,
                                       confirmed, domain=domain, expect_hash=expect_hash,
                                       runner=zoneedit_session.run)
    except Exception as ex:
        raise ToolError(f"zoneedit_record_delete failed: {zoneedit_tools.safe_error(ex)}") from None


def register_tools(server: GatedFastMCP) -> GatedFastMCP:
    """Register the two read tools and the three write tools on ``server``."""
    server.tool(
        name="zoneedit_records",
        annotations={"title": "ZoneEdit Records", "readOnlyHint": True,
                     "destructiveHint": False, "idempotentHint": True, "openWorldHint": True},
    )(zoneedit_records)
    server.tool(
        name="zoneedit_selftest",
        annotations={"title": "ZoneEdit Self-Test", "readOnlyHint": True,
                     "destructiveHint": False, "idempotentHint": True, "openWorldHint": True},
    )(zoneedit_selftest)
    server.tool(
        name="zoneedit_domains",
        annotations={"title": "ZoneEdit Domains", "readOnlyHint": True,
                     "destructiveHint": False, "idempotentHint": True, "openWorldHint": True},
    )(zoneedit_domains)
    server.tool(
        name="zoneedit_schema",
        annotations={"title": "ZoneEdit Record Schema", "readOnlyHint": True,
                     "destructiveHint": False, "idempotentHint": True, "openWorldHint": True},
    )(zoneedit_schema)
    server.tool(
        name="zoneedit_2fa_status",
        annotations={"title": "ZoneEdit 2FA Status", "readOnlyHint": True,
                     "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
    )(zoneedit_2fa_status)
    server.tool(
        name="zoneedit_2fa_latch_clear",
        annotations={"title": "ZoneEdit Clear Login Latch", "readOnlyHint": False,
                     "destructiveHint": False, "idempotentHint": False, "openWorldHint": False},
    )(zoneedit_2fa_latch_clear)
    server.tool(
        name="zoneedit_record_add",
        annotations={"title": "ZoneEdit Add Record", "readOnlyHint": False,
                     "destructiveHint": False, "idempotentHint": False, "openWorldHint": True},
    )(zoneedit_record_add)
    server.tool(
        name="zoneedit_record_update",
        annotations={"title": "ZoneEdit Update Record", "readOnlyHint": False,
                     "destructiveHint": True, "idempotentHint": False, "openWorldHint": True},
    )(zoneedit_record_update)
    server.tool(
        name="zoneedit_record_delete",
        annotations={"title": "ZoneEdit Delete Record", "readOnlyHint": False,
                     "destructiveHint": True, "idempotentHint": False, "openWorldHint": True},
    )(zoneedit_record_delete)
    return server


mcp = register_tools(build_server())


def _allowed_hosts(extra: str) -> tuple[list[str], list[str]]:
    hosts = ["127.0.0.1:*", "localhost:*", "[::1]:*"]
    origins = ["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"]
    for name in (h.strip() for h in extra.split(",")):
        if not name:
            continue
        hosts += [name, f"{name}:*"]
        origins += [f"http://{name}", f"http://{name}:*", f"https://{name}", f"https://{name}:*"]
    return hosts, origins


def build_http_app(server: GatedFastMCP, extra_hosts: str = ""):
    """The bearer-recording middleware around streamable_http_app(). Fails closed on stdio."""
    if is_stdio_transport():
        raise RuntimeError(
            f"refusing to build the HTTP app while {TRANSPORT_ENV}=stdio; "
            "the stdio skip would leave the mount ungated (fail closed)"
        )
    hosts, origins = _allowed_hosts(extra_hosts)
    server.settings.transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True, allowed_hosts=hosts, allowed_origins=origins
    )
    return BearerContextMiddleware(server.streamable_http_app())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="zoneedit-mcp")
    parser.add_argument("--transport", choices=("http", "stdio"), default="http")
    args = parser.parse_args(argv)

    os.environ[TRANSPORT_ENV] = args.transport
    configure_call_log()
    if args.transport == "stdio":
        mcp.run(transport="stdio")
        return 0

    if configured_hash() is None:
        print(
            f"zoneedit-mcp: refusing to start the HTTP mount: {HASH_ENV} is unset or is not a "
            "64-character SHA-256 hex digest (fail closed)",
            file=sys.stderr,
        )
        return 2

    import uvicorn

    mcp.settings.host = os.environ.get("ZONEEDIT_BIND_HOST", DEFAULT_BIND_HOST)
    mcp.settings.port = int(os.environ.get("ZONEEDIT_PORT", DEFAULT_PORT))
    app = build_http_app(mcp, os.environ.get("ZONEEDIT_ALLOWED_HOSTS", ""))
    uvicorn.Server(
        uvicorn.Config(app, host=mcp.settings.host, port=mcp.settings.port, log_level="info")
    ).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
