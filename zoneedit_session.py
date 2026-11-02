"""Headless browser session for the ZoneEdit control panel.

This is the only module that imports Patchright, and only inside functions, so tests never need a
browser. One login attempt and one second-factor attempt per run; a failed login or a rejected code
latches new runs for LATCH_S seconds; the browser is always closed; one run at a time.

Errors raised out of this module carry only the exception TYPE name and the final URL without its
query string. Patchright error messages echo filled values, so they are never kept.
"""
from __future__ import annotations

import math
import os
import re
import signal
import subprocess
import threading
import time
from typing import Any, Callable

from zoneedit_panel import parse_pages
from zoneedit_totp import seconds_left, totp
from zoneedit_vault import VaultError, get_credentials, get_totp_seed

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36"
)
LOGIN_URL = "https://cp.zoneedit.com/login.php"
DNS_HOME_URL = "https://cp.zoneedit.com/manage/domains/dns/"
SETTLE_MS = 1600            # the add form re-renders this long after a type change (measured on the panel)
MAX_SETTLE_TRIES = 3        # reads of one type's form before the type is listed as unsettled
OPTION_CAP = 80             # option lists longer than this are cut, with options_total added
PAGE_WAIT_MS = 1500
VIEWPORT = {"width": 1440, "height": 1000}
CHROME_ARGS_ENV = "ZONEEDIT_CHROME_ARGS"
LATCH_S = 900
TOTP_MIN_LEFT_S = 5
TOTP_STEP_S = 30
CODE_INPUT = ("input:visible:not([type=hidden]):not([type=checkbox]):not([type=submit])"
              ":not([type=button]):not([type=password])")
SUBMIT_BUTTON = "button[type=submit]:visible, input[type=submit]:visible"
RUN_DEADLINE_S = 150        # a run's worker may take this long before it is killed
LOCK_WAIT_S = 170           # a caller waits this long for the one run in progress
KILL_GRACE_S = 5            # after the kill, the worker gets this long to finish

_LOCK = threading.Lock()
_clock = time.monotonic
_BLOCKED_UNTIL = 0.0
_LAST_SUBMITTED_COUNTER: int | None = None   # the TOTP step of the last code this process submitted
_LAST_SECOND_FACTOR: str | None = None       # "answered" or "not_asked" for the last run; None before any
_LEAKED_WORKERS = 0                          # workers still alive after the kill and grace
_KILL_FAILURES = 0                           # kill attempts that raised; the deadline outcome still stands


def chrome_args() -> list[str]:
    """Extra Chromium flags from ZONEEDIT_CHROME_ARGS, split on whitespace. Unset or empty means none.
    Read at call time, not import time."""
    return os.environ.get(CHROME_ARGS_ENV, "").split()


class SecondFactorRequired(Exception):
    """The login was redirected to the two-factor page (tfa) and no usable TOTP seed is in the vault."""


class SecondFactorRejected(Exception):
    """The code page still shows after the one submit of the TOTP code."""


class LoginFailed(Exception):
    """The login page still shows after the one submit attempt."""


class LoginLatched(Exception):
    """A recent login or second-factor failure blocks new attempts."""


class SessionError(Exception):
    """A browser or page failure. Carries the exception type name and the URL, never a message."""

    def __init__(self, error_type: str, url: str):
        self.error_type = error_type
        self.url = url
        super().__init__(f"{error_type} at {url}" if url else error_type)


class RunDeadlineExceeded(SessionError):
    """The run's worker did not finish within RUN_DEADLINE_S; it was killed. Never a credential failure."""

    def __init__(self):
        super().__init__("RunDeadlineExceeded", "")


class RunBusy(SessionError):
    """Another run held the browser for LOCK_WAIT_S. No browser or credential was touched."""

    def __init__(self):
        super().__init__("RunBusy", "")


class UnknownDomain(Exception):
    """The named domain is not on the account, or the editor did not switch to it. ``domains`` is the list."""

    def __init__(self, domains):
        self.domains = list(domains)
        super().__init__("unknown_domain")


class DomainRequired(Exception):
    """No domain was named and the account holds several, so none is chosen. ``domains`` is the list."""

    def __init__(self, domains):
        self.domains = list(domains)
        super().__init__("domain_required")


class UnknownRecordType(Exception):
    """The named record type is not offered by the add form. ``types`` is the list the form offers."""

    def __init__(self, types):
        self.types = list(types)
        super().__init__("unknown_record_type")


_DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def valid_domain(name: str) -> bool:
    """Lowercase letters, digits and hyphens in at least two dot-separated labels, each 1 to 63 characters
    and not starting or ending with a hyphen; at most 253 characters. Nothing else: no scheme, path,
    query, space, uppercase or trailing dot."""
    if not isinstance(name, str) or len(name) > 253:
        return False
    labels = name.split(".")
    return len(labels) >= 2 and all(_DOMAIN_LABEL.fullmatch(label) for label in labels)


def dns_url_for(domain: str) -> str:
    """The DNS editor URL for one domain. Refuses a bad name before any navigation."""
    if not valid_domain(domain):
        raise ValueError("bad_domain")
    return f"{DNS_HOME_URL}index.php?LOGIN={domain}"


DOMAINS_LIST_URL = "https://cp.zoneedit.com/manage/domains/index.php?showall=1"

# The account's domain list page. Every link's LOGIN parameter is read with the URL API (raw values, in
# page order, duplicates kept); the total is the Y of the "out of Y total" text, or null.
DOMAIN_LIST_JS = """() => {
  const text = document.body ? document.body.innerText : '';
  const found = text.match(/out of\\s+(\\d+)\\s+total/i);
  const logins = [];
  document.querySelectorAll('a[href]').forEach((a) => {
    let value = null;
    try { value = new URL(a.getAttribute('href'), location.href).searchParams.get('LOGIN'); }
    catch (e) { value = null; }
    if (value !== null) { logins.push(value); }
  });
  return {logins: logins, total: found ? parseInt(found[1], 10) : null};
}"""

# The domain the DNS editor shows selected, or null. Read only after the editor has opened.
EDITOR_SELECTED_JS = """() => {
  const sel = document.querySelector('#selectDomain');
  const idx = sel ? sel.selectedIndex : -1;
  return idx >= 0 ? sel.options[idx].text.trim() : null;
}"""

TYPE_SELECT = "form[name=formAddRecord] select[name=type]"

TYPE_OPTIONS_JS = """() => Array.from(document.querySelectorAll('form[name=formAddRecord] select[name=type] option'))
  .map((o) => ({value: o.value, text: o.text.trim()}))"""

SELECTED_TYPE_JS = """() => {
  const sel = document.querySelector('form[name=formAddRecord] select[name=type]');
  return sel && sel.selectedIndex >= 0 ? sel.options[sel.selectedIndex].text.trim() : null;
}"""

SETTINGS_JS = """() => {
  const switches = {};
  document.querySelectorAll('input[role=switch][id]').forEach((s) => { switches[s.id] = s.checked === true; });
  const paging = document.querySelector('select[name=paging_size]');
  const idx = paging ? paging.selectedIndex : -1;
  return {switches: switches, paging_size: idx >= 0 ? paging.options[idx].text.trim() : null};
}"""

# Field names, labels, kinds, flags and select option texts only. Never a value: text inputs are
# described, not read. Scoped to the add form, so the settings token field is never reached.
CAPTURE_FIELDS_JS = """() => {
  const form = document.querySelector('form[name=formAddRecord]');
  if (!form) { return []; }
  const shown = (el) => {
    const box = el.getBoundingClientRect();
    return box.width > 0 && box.height > 0 && getComputedStyle(el).display !== 'none';
  };
  const labelOf = (el) => {
    let node = el.parentElement;
    while (node && node !== form) {
      const label = node.querySelector('.fw-light');
      if (label) { return label.textContent.replace(/\\s+/g, ' ').trim(); }
      node = node.parentElement;
    }
    return '';
  };
  const fields = [];
  form.querySelectorAll('input, textarea, select').forEach((el) => {
    const tag = el.tagName.toLowerCase();
    const type = (el.getAttribute('type') || '').toLowerCase();
    if (tag === 'input' && ['hidden', 'button', 'submit', 'reset', 'image'].includes(type)) { return; }
    if (tag === 'select' && el.name === 'type') { return; }
    if (!el.name || !shown(el)) { return; }
    const kind = tag === 'select' ? 'select' : tag === 'textarea' ? 'textarea'
      : type === 'checkbox' ? 'checkbox' : 'text';
    const field = {
      name: el.name, label: labelOf(el), kind: kind,
      required: el.required === true, disabled: el.disabled === true,
      placeholder: el.getAttribute('placeholder') || ''
    };
    if (kind === 'select') { field.options = Array.from(el.options).map((o) => o.text.trim()); }
    fields.push(field);
  });
  return fields;
}"""


def read_domains(page: Any) -> dict:
    """The account's domains from the domain list page, in page order, each once. Only names that pass
    valid_domain are kept. ``total`` is the Y of "out of Y total" (None when absent); ``complete`` says the
    list holds all of them; ``default`` is the name only when the account has exactly one domain."""
    page.goto(DOMAINS_LIST_URL, wait_until="domcontentloaded")
    page.wait_for_function(
        "/out of\\s+\\d+\\s+total/i.test(document.body ? document.body.innerText : '')", timeout=20000)
    listing = page.evaluate(DOMAIN_LIST_JS)
    domains: list[str] = []
    for value in listing["logins"]:
        if valid_domain(value) and value not in domains:
            domains.append(value)
    total = listing["total"]
    return {
        "domains": domains,
        "total": total,
        "complete": total is not None and len(domains) == total,
        "default": domains[0] if len(domains) == 1 else None,
    }


def open_domain(page: Any, domain: str = "") -> str:
    """Open the DNS editor for ``domain`` and return it. A bad name raises ValueError before any navigation.
    A name not on the account's list raises UnknownDomain with the list, and its editor URL is never
    requested. An empty name uses the account's only domain; with several it raises DomainRequired, with
    none UnknownDomain([]). The editor is always opened at dns_url_for(domain) and must show that domain."""
    if domain and not valid_domain(domain):
        raise ValueError("bad_domain")
    state = read_domains(page)
    if not domain:
        if len(state["domains"]) > 1:
            raise DomainRequired(state["domains"])
        if not state["domains"]:
            raise UnknownDomain([])
        domain = state["domains"][0]
    elif domain not in state["domains"]:
        raise UnknownDomain(state["domains"])
    return _open_editor(page, domain, state["domains"])


def _open_editor(page: Any, domain: str, listed: list[str]) -> str:
    """Load the editor for a name already read from the list, and check it shows that name selected.
    ``listed`` is the account's list, carried into UnknownDomain."""
    page.goto(dns_url_for(domain), wait_until="domcontentloaded")
    page.wait_for_selector("#selectDomain", timeout=20000)
    if page.evaluate(EDITOR_SELECTED_JS) != domain:
        raise UnknownDomain(listed)
    return domain


def read_settings(page: Any) -> dict:
    """The editor's switch states and the selected paging size. Nothing else on the page is read."""
    return page.evaluate(SETTINGS_JS)


def _shape(field: dict) -> dict:
    shaped = dict(field)
    if field["kind"] == "select" and len(field["options"]) > OPTION_CAP:
        shaped["options"] = field["options"][:OPTION_CAP]
        shaped["options_total"] = len(field["options"])
    return shaped


class SchemaUnavailable(Exception):
    """The add form's type did not settle, so its fields cannot be read. Carries no value."""

    def __init__(self):
        super().__init__("schema_unavailable")


def settled_fields(page: Any, type_text: str) -> tuple[list, bool]:
    """Read the add form's fields up to MAX_SETTLE_TRIES times, SETTLE_MS apart, for the type already selected.
    The form counts as settled only when the type select shows ``type_text`` and at least one field is present."""
    for _ in range(MAX_SETTLE_TRIES):
        page.wait_for_timeout(SETTLE_MS)
        fields = page.evaluate(CAPTURE_FIELDS_JS)
        if fields and page.evaluate(SELECTED_TYPE_JS) == type_text:
            return fields, True
    return [], False


def _type_fields(page: Any, option: dict) -> tuple[list, bool]:
    """Select one type, then read its form until it settles (see ``settled_fields``)."""
    page.locator(TYPE_SELECT).select_option(value=option["value"], timeout=15000)
    return settled_fields(page, option["text"])


def _open_add_form(page: Any) -> list:
    """Click the add button, wait for the type select, and return the type options (value and text)."""
    page.locator("#addBtn").click(timeout=15000)
    page.wait_for_selector(TYPE_SELECT, state="visible", timeout=20000)
    return page.evaluate(TYPE_OPTIONS_JS)


def ttl_labels(fields: list) -> list[str]:
    """The TTL option labels of a type's shaped fields, or [] when the type has no TTL select."""
    ttl = next((f for f in fields if f["name"] == "ttl" and f["kind"] == "select"), None)
    return list(ttl["options"]) if ttl else []


def schema_open(page: Any, record_type: str) -> dict:
    """The add form's type names, one type's fields and its TTL labels, for the write path.

    Refuses before any click when ``record_type`` (compared uppercased) is not offered: UnknownRecordType
    with the offered names. Clicks the add button and selects that one type; never submits. A type that does
    not settle raises SchemaUnavailable, so a write never proceeds without its schema."""
    options = _open_add_form_for(page, record_type)
    type_names = [option["text"] for option in options]
    match = [option for option in options if option["text"].upper() == record_type.upper()]
    fields, settled = _type_fields(page, match[0])
    if not settled:
        raise SchemaUnavailable()
    shaped = [_shape(field) for field in fields]
    return {"type_names": type_names, "fields": shaped, "ttl_options": ttl_labels(shaped)}


def _open_add_form_for(page: Any, record_type: str) -> list:
    """The type options after the add button is clicked; raises UnknownRecordType when none matches."""
    options = _open_add_form(page)
    if not any(option["text"].upper() == record_type.upper() for option in options):
        raise UnknownRecordType([option["text"] for option in options])
    return options


def read_schema(page: Any, domain: str = "", record_type: str = "") -> dict:
    """The add form's record types, their fields, the TTL labels, and the editor settings for one domain.

    Clicks only the add button and changes the type select; never submits. A type that never settles is
    listed in ``unsettled`` with no fields. ``record_type`` (compared uppercased) narrows the capture."""
    active = open_domain(page, domain)
    settings = read_settings(page)
    options = _open_add_form(page)
    type_names = [option["text"] for option in options]
    if record_type:
        options = [option for option in options if option["text"].upper() == record_type.upper()]
        if not options:
            raise UnknownRecordType(type_names)
    types: dict = {}
    unsettled: list[str] = []
    ttl_options: list[str] | None = None
    for option in options:
        fields, settled = _type_fields(page, option)
        if not settled:
            unsettled.append(option["text"])
            continue
        shaped = [_shape(field) for field in fields]
        types[option["text"].upper()] = {"fields": shaped}
        ttl = next((f for f in shaped if f["name"] == "ttl" and f["kind"] == "select"), None)
        if ttl_options is None and ttl is not None:
            ttl_options = list(ttl["options"])
    return {
        "domain": active,
        "type_names": type_names,
        "types": types,
        "ttl_options": ttl_options or [],
        "settings": settings,
        "type_count": len(type_names),
        "unsettled": unsettled,
        "complete": not unsettled,
    }


def login(page: Any, user: str, password: str) -> None:
    """Fill the visible login fields once and submit. No retry."""
    page.goto(LOGIN_URL, wait_until="domcontentloaded")
    page.wait_for_timeout(2000)
    page.locator("input[type=email]:visible, input[type=text]:visible").first.fill(
        user, timeout=15000)
    page.locator("input[type=password]:visible").first.fill(password, timeout=15000)
    page.locator("button[type=submit]:visible, input[type=submit]:visible").first.click(
        timeout=15000)
    page.wait_for_load_state("domcontentloaded")
    page.wait_for_timeout(3000)
    if "tfa" in page.url:
        raise SecondFactorRequired()
    if "login" in page.url:
        raise LoginFailed()


def _counter(at: float) -> int:
    """The TOTP step number for epoch second ``at``."""
    return int(at // TOTP_STEP_S)


def answer_second_factor(page: Any) -> None:
    """Enter the current TOTP code on the second-factor page and submit it once.

    The ZoneEdit code page has never been seen, so the selectors are generic and this entry is
    fixture-tested only, unproven live. A missing or invalid seed raises SecondFactorRequired (the
    old stop-and-report). A code still on the page after the submit raises SecondFactorRejected.

    One code per TOTP step per process: a step whose counter is not greater than the last submitted
    one waits into the next step before the code is computed, so a reused code is never submitted.
    """
    global _LAST_SUBMITTED_COUNTER, _LAST_SECOND_FACTOR
    try:
        seed = get_totp_seed()
    except VaultError:
        raise SecondFactorRequired() from None
    now = time.time()
    if _LAST_SUBMITTED_COUNTER is not None and _counter(now) <= _LAST_SUBMITTED_COUNTER:
        page.wait_for_timeout(int((seconds_left(now, TOTP_STEP_S) + 1) * 1000))
        now = time.time()
    elif seconds_left(now, TOTP_STEP_S) < TOTP_MIN_LEFT_S:
        page.wait_for_timeout(int((seconds_left(now, TOTP_STEP_S) + 1) * 1000))
        now = time.time()
    code = totp(seed, now, step=TOTP_STEP_S)
    _LAST_SUBMITTED_COUNTER = _counter(now)
    page.locator(CODE_INPUT).first.fill(code, timeout=15000)
    submit = page.locator(SUBMIT_BUTTON)
    if submit.count() > 0:
        submit.first.click(timeout=15000)
    else:
        page.keyboard.press("Enter")
    page.wait_for_load_state("domcontentloaded")
    page.wait_for_timeout(3000)
    if "tfa" in page.url or "login" in page.url:
        raise SecondFactorRejected()
    _LAST_SECOND_FACTOR = "answered"


def _login_and_second_factor(page: Any, user: str, password: str) -> None:
    """One login, then at most one second-factor answer. A LoginFailed or a rejected code latches."""
    global _BLOCKED_UNTIL, _LAST_SECOND_FACTOR
    try:
        try:
            login(page, user, password)
        except SecondFactorRequired:
            answer_second_factor(page)
        else:
            _LAST_SECOND_FACTOR = "not_asked"
    except (LoginFailed, SecondFactorRejected):
        _BLOCKED_UNTIL = _clock() + LATCH_S
        raise


def second_factor_state() -> dict:
    """The second-factor state as plain values: no seed, no code. Reads module floats only, so it is
    safe from any thread and never logs in."""
    now = time.time()
    return {
        "last_second_factor": _LAST_SECOND_FACTOR,
        "latch_seconds_left": max(0, math.ceil(_BLOCKED_UNTIL - _clock())),
        "last_submitted_step": _LAST_SUBMITTED_COUNTER,
        "step_seconds_left": int(seconds_left(now, TOTP_STEP_S)),
        "epoch": int(now),
    }


def clear_latch() -> int:
    """Clear the login latch so the next run may log in. Returns the whole seconds that were left (0 when
    none). Assigns one module float, so it is safe from any thread."""
    global _BLOCKED_UNTIL
    left = max(0, math.ceil(_BLOCKED_UNTIL - _clock()))
    _BLOCKED_UNTIL = 0.0
    return left


def _page_one(page: Any) -> str:
    """Page 1 of the editor that is already open, as HTML. Never navigates."""
    page.wait_for_timeout(3000)
    return page.content()


def read_first_page(page: Any, domain: str = "") -> str:
    """Open ``domain`` (see ``open_domain``) and return its DNS page 1 as HTML."""
    open_domain(page, domain)
    return _page_one(page)


def read_open_pages(page: Any) -> list[str]:
    """Every page of the editor that is already open, as HTML: page 1, then each page n >= 2 by clicking
    its pagination link. Never navigates, so a caller that ran ``open_domain`` does not load it twice."""
    first = _page_one(page)
    expected = parse_pages(first)
    pages = [first]
    for number in range(2, expected + 1):
        page.locator("nav[aria-label='DNS pagination'] a.page-link").filter(
            has_text=re.compile(rf"^\s*{number}\s*$")).first.click(timeout=15000)
        page.wait_for_timeout(PAGE_WAIT_MS)
        pages.append(page.content())
    return pages


def read_pages_domain(page: Any, domain: str = "") -> tuple[str, list[str]]:
    """Open ``domain`` and return (the domain actually open, every DNS page of it as HTML)."""
    active = open_domain(page, domain)
    return active, read_open_pages(page)


def read_pages(page: Any, domain: str = "") -> list[str]:
    """Every DNS page of ``domain`` (or the account's only domain) as HTML."""
    return read_pages_domain(page, domain)[1]


_BULK_SAVE = "#editor_bulk_save_mode"


def read_bulk_save_off(page: Any) -> bool | None:
    """True only when exactly one bulk-save switch is on the live page and unchecked.

    None for zero or many matches. Reads the live ``checked`` property: a saved snapshot cannot
    show it.
    """
    switch = page.locator(_BULK_SAVE)
    if switch.count() != 1:
        return None
    return not switch.is_checked(timeout=15000)


def read_first_page_with_bulk(page: Any, domain: str = "") -> tuple[str, bool | None, str]:
    """The DNS page 1 HTML, the live bulk-save state and the domain open, read in the same browser run.

    With no name and several domains, the first listed domain is opened instead of refusing (the selftest
    read). The same page is used, so there is no second login."""
    try:
        active = open_domain(page, domain)
    except DomainRequired as ex:
        active = _open_editor(page, ex.domains[0], ex.domains)
    html = _page_one(page)
    return html, read_bulk_save_off(page), active


def _final_url(page: Any) -> str:
    if page is None:
        return ""
    try:
        return str(page.url).split("?", 1)[0]
    except Exception:
        return ""


def user_agent_for(browser: Any) -> str:
    """USER_AGENT with the major version of the installed Chrome. Falls back to USER_AGENT."""
    version = getattr(browser, "version", None)
    if not isinstance(version, str):
        return USER_AGENT
    major = version.split(".", 1)[0]
    if not re.fullmatch(r"[0-9]+", major):
        return USER_AGENT
    return re.sub(r"Chrome/[0-9]+\.0\.0\.0", f"Chrome/{major}.0.0.0", USER_AGENT)


def _run_body(read: Callable[[Any], Any]) -> Any:
    """Open headless Chrome in a fresh context, log in once, return ``read(page)``. Runs in the worker."""
    global _LAST_SECOND_FACTOR
    _LAST_SECOND_FACTOR = None
    if _clock() < _BLOCKED_UNTIL:
        raise LoginLatched()
    user, password = get_credentials()
    page = None
    try:
        from patchright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                channel="chrome", headless=True, args=chrome_args())
            try:
                ua = user_agent_for(browser)
                context = browser.new_context(user_agent=ua, viewport=VIEWPORT)
                for name in ("set_default_timeout", "set_default_navigation_timeout"):
                    set_timeout = getattr(context, name, None)
                    if callable(set_timeout):
                        set_timeout(30000)
                page = context.new_page()
                _login_and_second_factor(page, user, password)
                return read(page)
            finally:
                browser.close()
    except (SecondFactorRequired, LoginFailed, SecondFactorRejected, LoginLatched):
        raise
    except Exception as ex:
        error_type = type(ex).__name__
        url = _final_url(page)
    raise SessionError(error_type, url)


def _worker(read: Callable[[Any], Any], box: dict) -> None:
    """The worker thread: stores ("ok", value) or ("err", exception) in this run's own box."""
    try:
        box["r"] = ("ok", _run_body(read))
    except BaseException as ex:
        box["r"] = ("err", ex)


_PROC = "/proc"


def _parent_from_stat(text: str) -> int:
    """The parent pid from one /proc/<pid>/stat line. The command name may hold spaces and ')'."""
    fields_after_comm = text[text.rindex(")") + 2:].split()
    return int(fields_after_comm[1])    # field 4 overall: the parent pid


def _parse_ps(text: str) -> dict[int, int]:
    """pid -> ppid from ``ps -axo pid=,ppid=`` output. Blank and malformed lines are skipped."""
    parents: dict[int, int] = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) != 2:
            continue
        try:
            parents[int(fields[0])] = int(fields[1])
        except ValueError:
            continue
    return parents


def _process_parents() -> dict[int, int]:
    """pid -> parent pid for every process. /proc on Linux; ``ps`` where /proc/self/stat is unreadable."""
    try:
        with open(os.path.join(_PROC, "self", "stat"), encoding="ascii", errors="replace"):
            pass
    except OSError:
        done = subprocess.run(["ps", "-axo", "pid=,ppid="], capture_output=True, text=True,
                              timeout=5, check=False)
        if done.returncode != 0:
            raise OSError("ps failed")
        return _parse_ps(done.stdout)
    parents: dict[int, int] = {}
    for name in os.listdir(_PROC):
        if not name.isdigit():
            continue
        try:
            with open(os.path.join(_PROC, name, "stat"), encoding="ascii", errors="replace") as handle:
                text = handle.read()
        except OSError:
            continue
        parents[int(name)] = _parent_from_stat(text)
    return parents


def _descendants(parents: dict[int, int], root: int) -> set[int]:
    """Every pid below ``root`` in the parent map. ``root`` itself is never in the result."""
    children: dict[int, list[int]] = {}
    for pid, ppid in parents.items():
        children.setdefault(ppid, []).append(pid)
    found: set[int] = set()
    todo = [root]
    while todo:
        for child in children.get(todo.pop(), []):
            if child != root and child not in found:
                found.add(child)
                todo.append(child)
    return found


def _kill_descendants() -> int:
    """SIGKILL every descendant of this process (never this process). Returns how many were signalled."""
    found = _descendants(_process_parents(), os.getpid())
    signalled = 0
    for pid in found:
        try:
            os.kill(pid, signal.SIGKILL)
            signalled += 1
        except (ProcessLookupError, PermissionError):
            continue
    return signalled


def run(read: Callable[[Any], Any]) -> Any:
    """Open headless Chrome in a fresh context, log in once, return ``read(page)``.

    The body runs in a worker thread under a deadline. One run at a time: a caller waits at most
    LOCK_WAIT_S for the lock, else RunBusy. A worker still alive at the deadline is killed (its
    descendant processes), given KILL_GRACE_S, and the run raises RunDeadlineExceeded; a result that
    arrives after the deadline is discarded with its box.
    """
    global _LEAKED_WORKERS, _KILL_FAILURES
    if not _LOCK.acquire(timeout=LOCK_WAIT_S):
        raise RunBusy()
    try:
        box: dict = {}
        worker = threading.Thread(target=_worker, args=(read, box), daemon=True,
                                  name="zoneedit-run")
        worker.start()
        worker.join(RUN_DEADLINE_S)
        if worker.is_alive():
            try:
                _kill_descendants()
            except Exception:
                _KILL_FAILURES += 1      # a failed kill never replaces the deadline outcome
            worker.join(KILL_GRACE_S)
            if worker.is_alive():
                _LEAKED_WORKERS += 1
            raise RunDeadlineExceeded()
        kind, value = box["r"]
        if kind == "err":
            raise value
        return value
    finally:
        _LOCK.release()
