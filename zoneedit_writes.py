"""Write path for one account domain: pure plan rules, panel page actions, panel re-read verification and
DNS read-back.

One call is one browser run (``zoneedit_session.run``): open the named domain, read every page, read the
record type's form schema, plan, and when confirmed perform the page actions and re-read the panel. ``ok``
is decided by the panel re-read only. DNS read-back is informative and never changes ``ok``. Refusals are
returned as ``{"ok": False, "refused": <code>}``, never raised. Errors name a step or an exception type,
never a filled value.
"""
from __future__ import annotations

import re
import subprocess
from typing import Any, Callable

from zoneedit_panel import parse_records, parse_total, parse_pages
from zoneedit_session import (
    PAGE_WAIT_MS,
    DomainRequired,
    RunDeadlineExceeded,
    SchemaUnavailable,
    UnknownDomain,
    UnknownRecordType,
    dns_url_for,
    open_domain,
    read_bulk_save_off,
    read_open_pages,
    read_pages,
    schema_open,
    settled_fields,
    valid_domain,
)

DIG_NAME_SERVER_ARGS = ("+short", "+time=3", "+tries=1")
LOAD_WAIT_MS = 3000
ACTION_WAIT_MS = 1500
STEP_TIMEOUT_MS = 15000
DIG_TIMEOUT_S = 15
_LABELS = re.compile(r"[a-z0-9_*-]+(?:\.[a-z0-9_*-]+)*")
_HASH = re.compile(r"[0-9a-f]{1,64}")
_ROW_PAGE_LINK = "nav[aria-label='DNS pagination'] a.page-link:text-is('{}'):visible"
UNKNOWN_MESSAGE = "the change may be live; read the zone before retrying"
CHECKBOX_VALUES = ("true", "false", "1", "0", "yes", "no")
CAA_PARTS = ("flag", "tag", "provider")
BLANK_NAMES = ("host", "type", "ttl")   # never settable through ``fields``
DOTTED_TYPES = ("CNAME", "MX")


class WriteStepError(Exception):
    """A page step did not match exactly one visible element. Carries the step name only."""

    def __init__(self, step: str):
        self.step = step
        super().__init__(f"write step {step} did not match exactly one visible element")


class PanelRefusal(Exception):
    """The panel offered a replace confirmation. Stop; nothing further is clicked."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def domain_refusal(ex: Exception) -> dict:
    """The refusal dict for a domain exception. ``domains`` is the account's list."""
    if isinstance(ex, DomainRequired):
        return {"ok": False, "refused": "domain_required", "domains": ex.domains}
    return {"ok": False, "refused": "unknown_domain", "domains": ex.domains}


# --- Pure plan rules -------------------------------------------------------------------------

def valid_host(host: str, domain: str) -> bool:
    """``@`` for the apex, else a bare label path inside ``domain``: never ``domain`` itself and never a
    name ending in ``.`` + ``domain``. Another domain's name is a valid label path."""
    if host == "@":
        return True
    if len(host) > 253 or not _LABELS.fullmatch(host):
        return False
    return host != domain and not host.endswith("." + domain)


def _norm(text: str) -> str:
    """Non-breaking spaces read as plain spaces, and the ends are trimmed. Nothing else changes."""
    return text.replace(" ", " ").strip()


def _option_matches(value: str, option: str) -> bool:
    """A value matches an option when it equals the option text or the part before " - "."""
    text = _norm(option)
    return _norm(value) in (text, text.split(" - ", 1)[0])


def _dotted(type_: str, value: str) -> str:
    """CNAME and MX targets end with a dot; every other value is kept as given."""
    if type_ in DOTTED_TYPES and value and not value.endswith("."):
        return value + "."
    return value


def _row(type_: str, host: str, content: str, ttl: str, prio: str) -> dict:
    return {"type": type_, "host": host, "content": content, "ttl": ttl, "prio": prio}


def _hashes(rows: list[dict]) -> set[str]:
    return {row["hash"] for row in rows if row.get("hash")}


def _host_exact(fields: list) -> bool:
    """True when the type's host field is labelled Host and the type has no service field: the row's host
    is then exactly the requested label. Selector, arpa and service styles are not exact."""
    host = next((f for f in fields if f["name"] == "host"), None)
    if host is None or any(f["name"] == "service" for f in fields):
        return False
    return _norm(host.get("label", "")).lower() == "host"


def _build_values(type_: str, content: str, prio: str, fields: dict | None):
    """The form values a request asks for: legacy content (CAA split into flag, tag, provider), legacy
    prio, then ``fields``. Returns (values, content keys, None) or (None, [], refusal code)."""
    values: dict = {}
    content_keys: list[str] = []
    if content:
        if type_ == "CAA":
            parts = content.split()
            if len(parts) != 3:
                return None, [], "bad_caa"
            content_keys = list(CAA_PARTS)
            values.update(zip(CAA_PARTS, parts))
        else:
            content_keys = ["content"]
            values["content"] = _dotted(type_, content)
    if prio:
        values["prio"] = prio
    for name, value in (fields or {}).items():
        if name in BLANK_NAMES or name in values or not isinstance(value, str):
            return None, [], "bad_field"
        if value:
            values[name] = _dotted(type_, value) if name == "content" else value
    return values, content_keys, None


def _check_values(values: dict, fields_schema: list) -> str | None:
    """The refusal code for a value the schema does not take, or None. Runs before any click."""
    by_name = {f["name"]: f for f in fields_schema}
    if "prio" in values and ("prio" not in by_name or not values["prio"].isdigit()):
        return "bad_prio"
    for name, value in values.items():
        field = by_name.get(name)
        if field is None:
            return "unknown_field"
        # A disabled field takes exactly one value: the panel's own default, its placeholder.
        if field.get("disabled") and _norm(value) != _norm(field.get("placeholder", "")):
            return "field_disabled"
        options = field.get("options", [])
        # A truncated list (options_total above the listed count) cannot decide a refusal; the page step does.
        truncated = field.get("options_total", len(options)) > len(options)
        if field["kind"] == "select" and not truncated and not any(
                _option_matches(value, option) for option in options):
            return "bad_option"
        if field["kind"] == "checkbox" and _norm(value).lower() not in CHECKBOX_VALUES:
            return "bad_option"
    return None


def _missing_required(values: dict, fields_schema: list) -> list[str]:
    """Required fields the caller must supply. A disabled field is never the caller's: the panel fixes it at its
    default, and the page step leaves it there."""
    return [f["name"] for f in fields_schema
            if f.get("required") and not f.get("disabled") and f["name"] not in BLANK_NAMES
            and f["name"] not in values]


def _identify(rows: list[dict], type_: str, host: str, expect: str, expect_hash: str):
    """The one row of ``type_`` and ``host`` that matches ``expect`` (exact content) and ``expect_hash``
    (both when given). Returns (target, same rows, None) or (None, same rows, refusal code)."""
    if expect_hash and not _HASH.fullmatch(expect_hash):
        return None, [], "bad_hash"
    if not (expect or expect_hash):
        return None, [], "empty_content"
    same = [r for r in rows if r["host"] == host and r["type"] == type_]
    if not same:
        return None, same, "not_found"
    hits = same
    if expect:
        hits = [r for r in hits if r["content"] == expect]
    if expect_hash:
        hits = [r for r in hits if r.get("hash") == expect_hash]
    if not hits:
        return None, same, "content_mismatch"
    if len(hits) > 1:
        return None, same, "ambiguous"
    return hits[0], same, None


def _after_content(type_: str, values: dict, current: str) -> str:
    """The row's content after the write: the current content with the requested parts replaced."""
    if type_ == "CAA":
        base = dict(zip(CAA_PARTS, current.split())) if len(current.split()) == 3 else {}
        base.update({k: values[k] for k in CAA_PARTS if k in values})
        return " ".join(base[k] for k in CAA_PARTS) if len(base) == 3 else current
    return values.get("content", current)


def _plan_delete(rows: list[dict], type_: str, host: str, expect: str, expect_hash: str) -> dict:
    target, same, refusal = _identify(rows, type_, host, expect, expect_hash)
    if refusal:
        return {"refused": refusal}
    return {"action": "delete", "type": type_, "host": host, "content": "", "expect": target["content"],
            "expect_hash": expect_hash, "ttl": "", "prio": "", "values": {}, "schema_fields": [],
            "host_exact": False, "target": target, "before": same, "after": None,
            "before_hashes": _hashes(rows), "before_count": len(rows)}


def _plan_write(action: str, rows: list[dict], type_: str, host: str, content: str, expect: str,
                expect_hash: str, ttl: str, prio: str, fields: dict | None, schema: dict) -> dict:
    fields_schema = schema["fields"]
    if action == "update" and not (content or fields or ttl or prio):
        return {"refused": "empty_content"}
    values, content_keys, refusal = _build_values(type_, content, prio, fields)
    if refusal:
        return {"refused": refusal}
    if action == "add" and type_ == "MX" and "prio" not in values:
        return {"refused": "bad_prio"}
    refusal = _check_values(values, fields_schema)
    if refusal:
        return {"refused": refusal}
    if action == "add":
        missing = _missing_required(values, fields_schema)
        if "content" in missing:
            return {"refused": "empty_content"}
        if missing:
            return {"refused": "missing_field", "missing": missing}
    ttl_text = ""
    if ttl:
        ttl_text = next((o for o in schema["ttl_options"] if _norm(o) == _norm(ttl)), None)
        if ttl_text is None:
            return {"refused": "bad_ttl"}
    if action == "add":
        same = [r for r in rows if r["host"] == host and r["type"] == type_]
        others = [r for r in rows if r["host"] == host]
        if (type_ == "CNAME" and others) or any(r["type"] == "CNAME" for r in others):
            return {"refused": "cname_conflict"}
        target, before, current = None, same, ""
    else:
        target, before, refusal = _identify(rows, type_, host, expect, expect_hash)
        if refusal:
            return {"refused": refusal}
        current = target["content"]
        if content and _dotted(type_, content) == current:
            for key in content_keys:
                values.pop(key, None)
        if not values and not ttl_text:
            return {"refused": "no_change"}
    plan_content = _dotted(type_, content) if content else _dotted(type_, values.get("content", ""))
    return {"action": action, "type": type_, "host": host, "content": plan_content,
            "expect": current, "expect_hash": expect_hash, "ttl": ttl_text, "prio": values.get("prio", ""),
            "values": values, "schema_fields": fields_schema, "host_exact": _host_exact(fields_schema),
            "target": target, "before": before, "before_hashes": _hashes(rows),
            "before_count": len(rows),
            "after": _row(type_, host, _after_content(type_, values, current), ttl_text or (
                target or {}).get("ttl", ""), values.get("prio", (target or {}).get("prio", "")))}


def plan_write(action: str, rows: list[dict], *, type_: str, host: str, domain: str,
               content: str = "", expect: str = "", expect_hash: str = "", ttl: str = "",
               prio: str = "", fields: dict | None = None, schema: dict | None = None) -> dict:
    """The plan for one write in ``domain``, or ``{"refused": <code>}``. Pure: no browser, no network.

    ``schema`` is the form schema of the requested type (``schema_open``): ``type_names``, that type's
    ``fields`` and ``ttl_options``. Add and update require it; delete reads no schema."""
    host = host.lower()
    type_ = type_.strip().upper()
    if not type_:
        return {"refused": "bad_type"}
    if action == "delete":
        if not valid_host(host, domain):
            return {"refused": "bad_host"}
        return _plan_delete(rows, type_, host, expect, expect_hash)
    if schema is None:
        return {"refused": "schema_unavailable"}
    spelled = {name.upper(): name for name in schema["type_names"]}
    if type_ not in spelled:
        return {"refused": "bad_type"}
    type_ = spelled[type_]
    host_field = next((f for f in schema["fields"] if f["name"] == "host"), None)
    optional_host = host_field is not None and not host_field.get("required")
    fill_host = True
    # An optional host field: "" and "@" both mean the field is left empty (the apex row), and it is not filled.
    if optional_host and host in ("", "@"):
        host, fill_host = "@", False
    if not valid_host(host, domain):
        return {"refused": "bad_host"}
    planned = _plan_write(action, rows, type_, host, content, expect, expect_hash, ttl, prio, fields, schema)
    return planned if "refused" in planned else {**planned, "fill_host": fill_host}


def _rows(pages: list[str]) -> list[dict]:
    return [dict(row, page=number)
            for number, html in enumerate(pages, 1) for row in parse_records(html)]


def reread_complete(pages: list[str]) -> bool:
    """True when every page the panel announces was read and the row count matches its Total."""
    total = next((t for t in (parse_total(p) for p in pages) if t is not None), None)
    return total is not None and len(_rows(pages)) == total and len(pages) == parse_pages(pages[0])


def verify(plan: dict, pages: list[str]) -> list[str]:
    """What differs between the plan and a panel re-read. An empty list means verified. Every check is a
    set difference against the rows the plan was made from, so it needs no knowledge of the record type."""
    rows = _rows(pages)
    diffs = [] if reread_complete(pages) else ["re-read incomplete: not every page or row was read"]
    before = set(plan["before_hashes"])
    now = _hashes(rows)
    if plan["action"] == "delete":
        return diffs + _verify_delete(plan, rows, before, now)
    if plan["action"] == "add":
        return diffs + _verify_add(plan, rows, before, now)
    return diffs + _verify_update(plan, rows, before, now)


def _verify_delete(plan: dict, rows: list[dict], before: set, now: set) -> list[str]:
    diffs = []
    target = plan["target"]["hash"]
    left = [r for r in rows if r["type"] == plan["type"] and r["host"] == plan["host"]
            and r["content"] == plan["expect"]]
    if target in now:
        diffs.append("target row still present after delete")
    if left:
        diffs.append(f"matching row still present after delete: {len(left)}")
    if before - now - {target}:
        diffs.append(f"another row vanished: {len(before - now - {target})}")
    if len(rows) != plan["before_count"] - 1:
        diffs.append(f"row count changed by {len(rows) - plan['before_count']}, expected -1")
    if any(r["pending"] for r in left):
        diffs.append("row is pending (queued for deletion or revoked)")
    return diffs


def _verify_add(plan: dict, rows: list[dict], before: set, now: set) -> list[str]:
    new = [r for r in rows if r.get("hash") not in before]
    if len(new) != 1:
        return [f"expected exactly one new row, found {len(new)}"]
    row = new[0]
    diffs = []
    if before - now:
        diffs.append(f"another row vanished: {len(before - now)}")
    if row["type"] != plan["type"]:
        diffs.append("new row has another type")
    if plan["host_exact"] and row["host"] != plan["host"]:
        diffs.append("new row has another host")
    if plan["content"] and row["content"] != plan["content"]:
        diffs.append("new row content differs from the request")
    if plan["ttl"] and plan["ttl"] not in row["ttl"]:
        diffs.append("ttl not shown as requested")
    if row["pending"]:
        diffs.append("matching row is pending (queued or revoked, not published)")
    return diffs


def _verify_update(plan: dict, rows: list[dict], before: set, now: set) -> list[str]:
    diffs = []
    target = plan["target"]["hash"]
    if before - now - {target}:
        diffs.append(f"another row vanished: {len(before - now - {target})}")
    if len(now - before) > 1:
        diffs.append(f"expected at most one new row, found {len(now - before)}")
    same = [r for r in rows if r["type"] == plan["type"] and r["host"] == plan["host"]]
    if len(same) != 1:
        diffs.append(f"expected exactly 1 row of this type and host, found {len(same)}")
    if any(r["pending"] for r in same):
        diffs.append("matching row is pending (queued or revoked, not published)")
    if plan["content"] and plan["content"] != plan["expect"] and any(
            r["content"] == plan["expect"] for r in same):
        diffs.append("old row still present after update")
    if plan["content"] and not any(r["content"] == plan["content"] for r in same):
        diffs.append("updated row does not show the requested content")
    if plan["ttl"] and same and plan["ttl"] not in same[0]["ttl"]:
        diffs.append("ttl not shown as requested")
    return diffs


# --- Name servers (from the zone itself) -----------------------------------------------------

def _ns_names(values) -> list[str]:
    """Each value with one trailing dot stripped, kept only when it is a valid domain name, once, in order."""
    names: list[str] = []
    for value in values:
        name = value.strip()
        if name.endswith("."):
            name = name[:-1]
        if valid_domain(name) and name not in names:
            names.append(name)
    return names


def nameservers_from_rows(rows: list[dict]) -> list[str]:
    """The name servers the zone names itself: the contents of its apex NS rows."""
    return _ns_names(row["content"] for row in rows if row["type"] == "NS" and row["host"] == "@")


def _dig_nameservers(domain: str) -> list[str]:
    """The name servers from ``dig +short NS <domain>``, used when the zone shows none. Empty when
    ``dig`` is missing or times out."""
    args = ["dig", *DIG_NAME_SERVER_ARGS, "NS", domain]
    try:
        done = subprocess.run(args, capture_output=True, text=True, timeout=DIG_TIMEOUT_S, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    return _ns_names(done.stdout.splitlines())


# --- DNS read-back (informative only) --------------------------------------------------------

def _dns_norm(text: str) -> str:
    return " ".join(text.replace('"', "").strip().rstrip(".").split()).lower()


def dns_readback(action: str, type_: str, host: str, needle: str, domain: str,
                 nameservers: list[str]) -> tuple[dict, dict]:
    """Ask each name server with the system ``dig``. Returns (lines per server, match per server).

    The needle is the content (add, update) or the expected content (delete). For ``delete`` the match
    means the old content is GONE. An empty needle still lists every server's lines but returns no matches.
    No name server gives ``({"error": "no_nameservers"}, {})``; a missing ``dig`` gives
    ``({"error": "dig_unavailable"}, {})``. Neither fails the write.
    """
    if not nameservers:
        return {"error": "no_nameservers"}, {}
    fqdn = domain if host == "@" else f"{host}.{domain}"
    target = _dns_norm(needle)
    readback: dict = {}
    matches: dict = {}
    for ns in nameservers:
        args = ["dig", *DIG_NAME_SERVER_ARGS, f"@{ns}", fqdn, type_]
        try:
            done = subprocess.run(args, capture_output=True, text=True,
                                  timeout=DIG_TIMEOUT_S, check=False)
        except FileNotFoundError:
            return {"error": "dig_unavailable"}, {}
        except subprocess.TimeoutExpired:
            readback[ns] = {"lines": [], "error": "timeout"}
            matches[ns] = False
            continue
        lines = [line for line in done.stdout.splitlines() if line.strip()]
        readback[ns] = {"lines": lines}
        present = any(_dns_norm(line) == target for line in lines)
        matches[ns] = (not present) if action == "delete" else present
    return readback, (matches if target else {})


# --- Page actions ----------------------------------------------------------------------------

def _one(page: Any, selector: str, step: str):
    """The single element a selector must match. Any other count is a step failure."""
    locator = page.locator(selector)
    if locator.count() != 1:
        raise WriteStepError(step)
    return locator


def _row_scope(hash_: str) -> str:
    if not _HASH.fullmatch(hash_):
        raise WriteStepError("row_hash")
    return f"div.item-wrapped[data-hash='{hash_}']"


def _goto_dns(page: Any, domain: str, number: int = 1) -> None:
    """The DNS editor of ``domain`` (already validated by the caller's plan), page ``number``."""
    page.goto(dns_url_for(domain), wait_until="domcontentloaded")
    page.wait_for_timeout(LOAD_WAIT_MS)
    if number > 1:
        links = page.locator(_ROW_PAGE_LINK.format(int(number)))
        if links.count() < 1:
            raise WriteStepError("pagination")
        links.first.click(timeout=STEP_TIMEOUT_MS)
        page.wait_for_timeout(PAGE_WAIT_MS)


def _click_add_button(page: Any) -> None:
    buttons = page.locator("button:visible, a:visible")
    hits = []
    for i in range(buttons.count()):
        text = " ".join(buttons.nth(i).inner_text(timeout=STEP_TIMEOUT_MS).split())
        if "ADD" in text and "Domain" not in text and "Zone" not in text:
            hits.append(i)
    if not hits:
        raise WriteStepError("add_button")
    buttons.nth(hits[-1]).click(timeout=STEP_TIMEOUT_MS)
    page.wait_for_timeout(ACTION_WAIT_MS)


def _refuse_on_confirm(page: Any, scope: str) -> None:
    """A visible Confirm button or a shown replace warning stops the run. Nothing is clicked."""
    shown = page.locator(f"{scope} button.btn-warning:visible, "
                         f"{scope} [data-field^='warn_']:visible").count()
    if shown:
        raise PanelRefusal("replace_prompt_shown")


def _field_selector(scope: str, field: dict) -> str:
    """The element a schema field names inside ``scope``. Names come from the panel's own schema."""
    tag = {"textarea": "textarea", "select": "select"}.get(field["kind"], "input")
    return f"{scope} {tag}[name={field['name']}]"


def _css_string(value: str) -> str:
    """A CSS double-quoted string for an option value, so a value can never close the selector early."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _parse_bool(value: str) -> bool:
    return _norm(value).lower() in ("true", "1", "yes")


def _select_option(page: Any, select: str, value: str, step: str) -> None:
    """Choose one option: by exact value attribute, else exact option text, else the text before " - ".
    Exactly one match in each tier, else a step failure that names the step, never the value."""
    if page.locator(f"{select} option[value={_css_string(value)}]").count() == 1:
        _one(page, select, step).select_option(value=value, timeout=STEP_TIMEOUT_MS)
        return
    texts = page.locator(f"{select} option").all_inner_texts()
    exact = [t for t in texts if _norm(t) == _norm(value)]
    if len(exact) == 1:
        _one(page, select, step).select_option(label=exact[0], timeout=STEP_TIMEOUT_MS)
        return
    prefixed = [t for t in texts if _norm(t).split(" - ", 1)[0] == _norm(value)]
    if len(prefixed) != 1:
        raise WriteStepError(step)
    _one(page, select, step).select_option(label=prefixed[0], timeout=STEP_TIMEOUT_MS)


def _fill_field(page: Any, scope: str, field: dict, value: str, step: str) -> None:
    """One generic field fill: text and textarea by fill, select by option choice, checkbox by set_checked."""
    selector = _field_selector(scope, field)
    if field["kind"] == "select":
        _select_option(page, selector, value, step)
    elif field["kind"] == "checkbox":
        _one(page, selector, step).set_checked(_parse_bool(value), timeout=STEP_TIMEOUT_MS)
    else:
        _one(page, selector, step).fill(value, timeout=STEP_TIMEOUT_MS)


def _fill_values(page: Any, scope: str, type_: str, fields_schema: list, values: dict) -> None:
    """Fill the requested values in schema order, on the add form and on an edit. A field the live form
    disables keeps its default (its value, else its placeholder): a request equal to it is skipped, any other
    request fails the step before any click."""
    for field in fields_schema:
        name = field["name"]
        if name not in values:
            continue
        step = f"caa_{name}" if type_ == "CAA" else name
        element = _one(page, _field_selector(scope, field), step)
        if not element.is_enabled():
            current = _norm(element.input_value()) or _norm(field.get("placeholder", ""))
            if current == _norm(values[name]):
                continue
            raise WriteStepError("field_disabled")
        _fill_field(page, scope, field, values[name], step)


def _select_ttl(page: Any, scope: str, label: str) -> None:
    options = page.locator(f"{scope} select[name=ttl] option").all_inner_texts()
    if label not in options:
        raise WriteStepError("ttl_option")
    _one(page, f"{scope} select[name=ttl]", "ttl_select").select_option(
        label=label, timeout=STEP_TIMEOUT_MS)


def _add(page: Any, plan: dict, domain: str, state: dict | None = None) -> None:
    _goto_dns(page, domain)
    _click_add_button(page)
    form = "form[name=formAddRecord]:visible"
    _one(page, f"{form} select[name=type]", "add_type").select_option(
        plan["type"], timeout=STEP_TIMEOUT_MS)
    _, settled = settled_fields(page, plan["type"])  # the form re-renders when the type changes
    if not settled:
        raise WriteStepError("add_type")
    if plan["fill_host"]:
        _one(page, f"{form} input[name=host]", "add_host").fill(plan["host"], timeout=STEP_TIMEOUT_MS)
    _fill_values(page, form, plan["type"], plan["schema_fields"], plan["values"])
    if plan["ttl"]:
        _select_ttl(page, form, plan["ttl"])
    _refuse_on_confirm(page, form)
    _one(page, f"{form} button[type=submit].btn-success:visible", "add_save").click(
        timeout=STEP_TIMEOUT_MS)
    _mark_final(state)
    page.wait_for_timeout(ACTION_WAIT_MS)
    _refuse_on_confirm(page, form)


def _change(page: Any, plan: dict, domain: str, state: dict | None = None) -> None:
    target = plan["target"]
    row = _row_scope(target["hash"])
    _goto_dns(page, domain, target.get("page", 1))
    _one(page, row, "row")
    _one(page, f"{row} button.btn-edit:visible", "edit_button").click(timeout=STEP_TIMEOUT_MS)
    page.wait_for_timeout(ACTION_WAIT_MS)
    edit = f"{row} form[name=formEditRecord]:visible"
    if plan["action"] == "delete":
        _one(page, f"{edit} button.btn-danger:visible:has-text('Delete')", "delete_button").click(
            timeout=STEP_TIMEOUT_MS)
        _mark_final(state)
        page.wait_for_timeout(ACTION_WAIT_MS)
        return
    _fill_values(page, edit, plan["type"], plan["schema_fields"], plan["values"])
    if plan["ttl"]:
        _select_ttl(page, edit, plan["ttl"])
    _refuse_on_confirm(page, edit)
    _one(page, f"{edit} button.btn-success:visible", "edit_save").click(timeout=STEP_TIMEOUT_MS)
    _mark_final(state)
    page.wait_for_timeout(ACTION_WAIT_MS)
    _refuse_on_confirm(page, edit)


def _mark_final(state: dict | None) -> None:
    """Record that the final Save or Delete click has returned: the change may now be live."""
    if state is not None:
        state["final_clicked"] = True


def _perform(page: Any, plan: dict, state: dict, domain: str) -> None:
    if plan["action"] == "add":
        _add(page, plan, domain, state)
    else:
        _change(page, plan, domain, state)


def _unknown(ex: BaseException, shown: dict) -> dict:
    """A failure after the final click: the outcome is indeterminate, never a refusal."""
    out = {"ok": False, "confirmed": True, "outcome": "unknown", "message": UNKNOWN_MESSAGE,
           "error_type": type(ex).__name__, **shown}
    if isinstance(ex, WriteStepError):
        out["step"] = ex.step
    return out


# --- Orchestration ---------------------------------------------------------------------------

def _run(page: Any, *, action: str, type_: str, host: str, content: str, expect: str, expect_hash: str,
         ttl: str, prio: str, fields: dict | None, confirmed: bool, domain: str, state: dict) -> dict:
    """One run's body: open the named domain first, then the checks in order, then the write. ``state``
    is shared with ``write_record``: it carries ``final_clicked`` and, once verified, ``nameservers``."""
    try:
        active = open_domain(page, domain)
    except ValueError:
        return {"ok": False, "refused": "bad_domain", "domain": None}
    except (DomainRequired, UnknownDomain) as ex:
        return {**domain_refusal(ex), "domain": None}
    pages = read_open_pages(page)
    if read_bulk_save_off(page) is not True:
        return {"ok": False, "refused": "bulk_save_on_or_unknown", "domain": active}
    if not reread_complete(pages):
        return {"ok": False, "refused": "incomplete_read", "domain": active}
    schema = None
    type_key = type_.strip().upper()
    if action != "delete" and type_key:
        try:
            schema = schema_open(page, type_)
        except UnknownRecordType:
            return {"ok": False, "action": action, "refused": "bad_type", "domain": active}
        except SchemaUnavailable:
            return {"ok": False, "action": action, "refused": "schema_unavailable", "domain": active}
    plan = plan_write(action, _rows(pages), type_=type_, host=host, domain=active, content=content,
                      expect=expect, expect_hash=expect_hash, ttl=ttl, prio=prio, fields=fields,
                      schema=schema)
    if "refused" in plan:
        return {"ok": False, "action": action, **plan, "domain": active}
    shown = {"action": action, "before": plan["before"], "after": plan["after"], "domain": active,
             "values": plan["values"]}
    if not confirmed:
        return {"ok": True, "confirmed": False, **shown}
    state["final_clicked"] = False
    try:
        _perform(page, plan, state, active)
    except PanelRefusal as ex:
        if not state["final_clicked"]:
            return {"ok": False, "confirmed": True, "refused": ex.reason, **shown}
        return _unknown(ex, shown)
    except WriteStepError as ex:
        if not state["final_clicked"]:
            return {"ok": False, "confirmed": True, "refused": "step_failed", "step": ex.step,
                    **shown}
        return _unknown(ex, shown)
    except Exception as ex:
        if not state["final_clicked"]:
            raise
        return _unknown(ex, shown)
    try:
        after = read_pages(page, active)
        diffs = verify(plan, after)
    except Exception as ex:
        return _unknown(ex, shown)
    state["nameservers"] = nameservers_from_rows(_rows(after))
    verified = not diffs
    result = {"ok": verified, "confirmed": True, **shown,
              "panel_verified": verified, "verified": verified}
    if diffs:
        result["differences"] = diffs
    return result


def write_record(runner: Callable[[Callable[[Any], Any]], Any], action: str, *, type_: str,
                 host: str, content: str = "", expect: str = "", expect_hash: str = "", ttl: str = "",
                 prio: str = "", fields: dict | None = None, confirmed: bool = False,
                 domain: str = "") -> dict:
    """One browser run for one write in ``domain`` (empty: the account's only domain). A bad name is
    refused before any browser run. DNS read-back runs only after a verified panel write, against the
    name servers the zone shows, else the NS answer of ``dig``."""
    if domain and not valid_domain(domain):
        return {"ok": False, "refused": "bad_domain", "domain": None}
    state: dict = {}

    def do(page: Any) -> dict:
        return _run(page, action=action, type_=type_, host=host, content=content, expect=expect,
                    expect_hash=expect_hash, ttl=ttl, prio=prio, fields=fields, confirmed=confirmed,
                    domain=domain, state=state)

    try:
        result = runner(do)
    except RunDeadlineExceeded:
        if not confirmed:
            raise
        # The cut run may have clicked the final save: the caller must read the zone before any retry.
        return {"ok": False, "confirmed": True, "outcome": "unknown", "message": UNKNOWN_MESSAGE,
                "error_type": "RunDeadlineExceeded", "action": action, "domain": domain or None}
    if result.get("panel_verified") is True:
        active = result["domain"]
        needle = expect if action == "delete" else content
        nameservers = state.get("nameservers") or _dig_nameservers(active)
        readback, matches = dns_readback(action, type_, host.lower(), needle, active, nameservers)
        result["dns_readback"] = readback
        result["dns_matches"] = matches
    return result
