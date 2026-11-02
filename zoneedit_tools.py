"""Plain tool functions for zoneedit-mcp. ``runner`` is ``zoneedit_session.run`` in production and a
fake in tests; it is called with a read function and returns that function's result."""
from __future__ import annotations

from typing import Any, Callable

from zoneedit_panel import parse_pages, parse_records, parse_total
from zoneedit_session import (
    DomainRequired,
    LoginFailed,
    LoginLatched,
    SecondFactorRejected,
    SecondFactorRequired,
    UnknownDomain,
    UnknownRecordType,
    clear_latch,
    read_domains,
    read_first_page_with_bulk,
    read_pages_domain,
    read_schema,
    second_factor_state,
    valid_domain,
)
from zoneedit_vault import VaultError, get_totp_seed
from zoneedit_writes import domain_refusal, write_record


def safe_error(exc: BaseException) -> str:
    """The exception type name only. Never the message."""
    return getattr(exc, "error_type", None) or type(exc).__name__


def _warning(read: int, total: int | None, pages_read: int, pages_expected: int,
             complete: bool) -> str:
    total_text = "unknown (no Total found)" if total is None else str(total)
    message = (f"Read {read} of {total_text} panel records from {pages_read} of "
               f"{pages_expected} pages. ")
    if not complete:
        message += "Incomplete: the read did not cover the whole zone. "
    if read == 0:
        message += "Zero records read: this is not proof that the zone has no records."
    return message.strip()


def _domain_refusal(ex: Exception) -> dict:
    if isinstance(ex, UnknownRecordType):
        return {"ok": False, "refused": "unknown_record_type", "types": ex.types}
    return domain_refusal(ex)


def domains(*, runner: Callable[[Callable[[Any], Any]], Any]) -> dict:
    """The account's domains from the domain list page, with its total and whether the list is complete."""
    state = runner(read_domains)
    return {"domains": state["domains"], "default": state["default"], "count": len(state["domains"]),
            "total": state["total"], "complete": state["complete"]}


def schema(domain: str = "", record_type: str = "", *,
           runner: Callable[[Callable[[Any], Any]], Any]) -> dict:
    """The record types, form fields, TTL labels and editor settings of one domain (default: the current)."""
    if domain and not valid_domain(domain):
        return {"ok": False, "refused": "bad_domain"}

    def read(page: Any) -> Any:
        try:
            return read_schema(page, domain, record_type)
        except (DomainRequired, UnknownDomain, UnknownRecordType) as ex:
            return ex

    result = runner(read)
    if isinstance(result, (DomainRequired, UnknownDomain, UnknownRecordType)):
        return _domain_refusal(result)
    return result


def records(host: str = "", domain: str = "", *,
            runner: Callable[[Callable[[Any], Any]], Any]) -> dict:
    """Read every DNS page of one domain and return the records, optionally filtered to one host (``@`` apex).

    An empty ``domain`` means the account's only domain; with several it is refused (domain_required).
    The result always carries ``domain``, the domain actually read."""
    if domain and not valid_domain(domain):
        return {"ok": False, "refused": "bad_domain", "domain": None}

    def read(page: Any) -> Any:
        try:
            return read_pages_domain(page, domain)
        except (DomainRequired, UnknownDomain) as ex:
            return ex

    out = runner(read)
    if isinstance(out, (DomainRequired, UnknownDomain)):
        return {**_domain_refusal(out), "domain": None}
    active, pages = out
    result = _records_result(pages, host)
    result["domain"] = active
    return result


def _records_result(pages: list[str], host: str) -> dict:
    first = pages[0] if pages else ""
    panel_total = next((t for t in (parse_total(p) for p in pages) if t is not None), None)
    pages_expected = parse_pages(first)
    rows = [row for page in pages for row in parse_records(page)]
    matches = [row for row in rows if not host or row["host"] == host]
    complete = (panel_total is not None and len(rows) == panel_total
                and len(pages) == pages_expected)
    result = {
        "records": matches,
        "read": len(rows),
        "panel_total": panel_total,
        "pages_read": len(pages),
        "pages_expected": pages_expected,
        "complete": complete,
        "filter": host,
        "matched": len(matches),
    }
    if not complete or not rows:
        result["warning"] = _warning(len(rows), panel_total, len(pages), pages_expected, complete)
    return result


def _seed_status() -> str:
    """Seed status: present, absent (no entry or unreadable) or invalid (the entry is malformed). Never the value."""
    try:
        get_totp_seed()
    except VaultError as ex:
        message = str(ex)
        if message.startswith(("vault_seed_invalid", "vault_field_missing")):
            return "invalid"
        return "absent"
    return "present"


def _seed_presence() -> str:
    """Seed presence for the selftest: present or absent. A malformed entry counts as absent."""
    return "present" if _seed_status() == "present" else "absent"


def selftest(domain: str = "", *, runner: Callable[[Callable[[Any], Any]], Any]) -> dict:
    """Log in, read the DNS page 1 of ``domain`` (empty: the first listed domain when there are several) and
    report its shape. Never returns a value or a message.

    ``second_factor`` says whether the last login answered the code page. The seed is read only when
    it did, so a password-only login never touches the seed."""
    if domain and not valid_domain(domain):
        return {"ok": False, "refused": "bad_domain"}

    def read(page: Any) -> Any:
        try:
            return read_first_page_with_bulk(page, domain)
        except UnknownDomain as ex:
            return ex

    try:
        out = runner(read)
    except SecondFactorRequired:
        return {"ok": False, "error_type": "second_factor_required"}
    except SecondFactorRejected:
        return {"ok": False, "error_type": "second_factor_rejected"}
    except LoginFailed:
        return {"ok": False, "error_type": "login_failed"}
    except LoginLatched:
        return {"ok": False, "error_type": "login_latched"}
    except Exception as ex:
        return {"ok": False, "error_type": safe_error(ex)}
    if isinstance(out, UnknownDomain):
        return _domain_refusal(out)
    first, bulk, active = out
    panel_total = parse_total(first)
    second_factor = second_factor_state()["last_second_factor"] or "unknown"
    return {
        "login": "ok",
        "domain": active,
        "dns_page": panel_total is not None,
        "panel_total": panel_total,
        "pages": parse_pages(first),
        "bulk_save_off": bulk,
        "second_factor": second_factor,
        "seed": _seed_presence() if second_factor == "answered" else "not_read",
    }


def twofa_status() -> dict:
    """The second-factor state and the seed's status. Never logs in, never opens a browser, never
    returns the seed or a code."""
    return {"seed": _seed_status(), **second_factor_state()}


def twofa_latch_clear(confirmed: bool) -> dict:
    """Clear the login latch. Previews the seconds left unless ``confirmed`` is True."""
    if confirmed is not True:
        return {"ok": True, "confirmed": False,
                "latch_seconds_left": second_factor_state()["latch_seconds_left"],
                "action": "clear_latch"}
    return {"ok": True, "confirmed": True, "cleared_seconds": clear_latch(), "action": "clear_latch"}


def record_add(type_: str, host: str, content: str = "", ttl: str = "", prio: str = "",
               confirmed: bool = False, *, domain: str = "", fields: dict | None = None,
               runner: Callable[[Callable[[Any], Any]], Any]) -> dict:
    """Plan an add in ``domain``; write it only when confirmed. See ``zoneedit_writes.write_record``."""
    return write_record(runner, "add", type_=type_, host=host, content=content, ttl=ttl,
                        prio=prio, fields=fields, confirmed=confirmed, domain=domain)


def record_update(type_: str, host: str, expect_content: str = "", new_content: str = "",
                  new_ttl: str = "", new_prio: str = "", confirmed: bool = False, *,
                  domain: str = "", expect_hash: str = "", fields: dict | None = None,
                  runner: Callable[[Callable[[Any], Any]], Any]) -> dict:
    """Plan an update of one row read in this call; write it only when confirmed."""
    return write_record(runner, "update", type_=type_, host=host, expect=expect_content,
                        expect_hash=expect_hash, content=new_content, ttl=new_ttl, prio=new_prio,
                        fields=fields, confirmed=confirmed, domain=domain)


def record_delete(type_: str, host: str, expect_content: str = "", confirmed: bool = False, *,
                  domain: str = "", expect_hash: str = "",
                  runner: Callable[[Callable[[Any], Any]], Any]) -> dict:
    """Plan a delete of one row read in this call; delete only when confirmed."""
    return write_record(runner, "delete", type_=type_, host=host, expect=expect_content,
                        expect_hash=expect_hash, confirmed=confirmed, domain=domain)
