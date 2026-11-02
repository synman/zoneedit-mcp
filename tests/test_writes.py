"""Write tools: plan rules, page actions, orchestration and the server surface.

No browser, no network, no vault and no real ``dig``. Pages are saved HTML strings or a recording
fake page; ``read_pages`` and ``subprocess.run`` are monkeypatched where a run needs them.
"""
import asyncio
import subprocess
from pathlib import Path

import pytest
from mcp.server.fastmcp.exceptions import ToolError

import zoneedit_server as srv
import zoneedit_session as s
import zoneedit_tools as t
import zoneedit_writes as w
from zoneedit_panel import parse_records

FIXTURE = (Path(__file__).parent / "fixtures" / "dns_index.html").read_text(encoding="utf-8")
ROWS = parse_records(FIXTURE)
ADD_FORM = "form[name=formAddRecord]:visible"
ADD_BUTTON = "button:visible, a:visible"
HOME_HASH = "0561cdb77715b0b0a4ec5e0df3c7cfa7"
MEET_HASH = "6c563b24326786e448d2196f11d58326"
# The live panel's TTL labels (one with a non-breaking space) and a small schema table for A, CNAME, TXT,
# MX and CAA. The add form's CAA flag is enabled; the edit form's is disabled (see the page tests).
TTL_LABELS = ["[DEF] 2 hours", "5 minutes", "10 minutes", "15 minutes", "30 minutes", "1 hour", "3 hours",
              "6 hours", "12 hours", "1 day", "2 days", "3 days", "1 week", "10 days", "2 weeks"]


def _field(name, label, kind, required=False, disabled=False, options=None, placeholder=""):
    shaped = {"name": name, "label": label, "kind": kind, "required": required,
              "disabled": disabled, "placeholder": placeholder}
    if kind == "select":
        shaped["options"] = options
    return shaped


_HOST = _field("host", "Host", "text", required=True)
_TTL = _field("ttl", "TTL", "select", options=TTL_LABELS)
TABLE = {
    "A": [_HOST, _field("content", "IP address", "text", required=True), _TTL],
    "CNAME": [_HOST, _field("content", "Target", "text", required=True), _TTL],
    "TXT": [_HOST, _field("content", "Text", "textarea", required=True), _TTL],
    "MX": [_HOST, _field("content", "Mail server", "text", required=True),
           _field("prio", "Priority", "text", required=True), _TTL],
    "CAA": [_HOST, _field("flag", "Flag", "text", required=True, disabled=True, placeholder="0"),
            _field("tag", "Tag", "select", required=True, options=["issue", "issuewild", "iodef"]),
            _field("provider", "Provider", "select", required=True, options=["letsencrypt.org", "pki.goog", "sectigo.com"]),
            _TTL],
}


def schema_for(type_):
    """The schema ``schema_open`` returns for one type of the table (``type_names`` are the table's types)."""
    return {"type_names": list(TABLE), "fields": TABLE.get(type_.upper(), []), "ttl_options": TTL_LABELS}


def fake_schema_open(page, record_type):
    if record_type.upper() not in TABLE:
        raise s.UnknownRecordType(list(TABLE))
    return schema_for(record_type)


def _row(type_, host, content, h, ttl="[DEF] 2 hours", pending=False):
    icon = '<i aria-label="Queued record"></i>' if pending else ""
    return (f'<div class="item-wrapped row" data-hash="{h}">'
            f'<div class="col border-end item col-md-2">{type_}</div>'
            f'<div class="col col-md-4 border-end item">{host}</div>'
            f'<div class="col border-end item col-md-4"><span class="rdata">{content}</span></div>'
            f'<div class="col-md-1 col item">{ttl}</div>{icon}</div>')


def _page(rows, total=None, pages=1, bulk="false"):
    total = len(rows) if total is None else total
    labels = "".join(f'<li class="page-item"><a>{n}</a></li>' for n in range(1, pages + 1))
    nav = (f'<nav aria-label="DNS pagination"><div>Total: {total}</div>'
           f'<ul class="pagination">{labels}</ul></nav>')
    bulk_input = f'<input id="editor_bulk_save_mode" name="editor_bulk_save_mode" value="{bulk}">'
    return "<html><body>" + bulk_input + nav + "".join(rows) + "</body></html>"


def pages_of(rows, **kw):
    return [_page(rows, **kw)]


def _dict(type_, host, content, h):
    return {"type": type_, "host": host, "content": content, "ttl": "", "hash": h}


DOMAIN = "example.com"
BASE_NO_NS = [
    _row("CNAME", "home", "target.example.net.", "0561cdb77715b0b0a4ec5e0df3c7cfa7"),
    _row("CNAME", "meet", "target.example.net.", MEET_HASH),
    _row("CNAME", "mail", "example-com.mail.protection.outlook.com.", "4b15a2d194ea9c3119ac7d1c5bbfd568"),
    _row("CAA", "@", "0 issue letsencrypt.org", "65e3f174cd4ca4152c4074c18d628ec7"),
]
# The zone's own apex NS rows: the name servers the read-back asks.
NS_ROWS = [_row("NS", "@", "ns19.zoneedit.com.", "a1"), _row("NS", "@", "ns8.zoneedit.com.", "a2")]
BASE = BASE_NO_NS + NS_ROWS
BASE_NO_MEET = [r for r in BASE if "'meet'" not in r and ">meet<" not in r]
AFTER_UPDATE = [_row("CNAME", "home", "new.example.", HOME_HASH)] + BASE[1:]


def add_step(page, plan_):
    """The add page step for DOMAIN (the active domain a real run would pass)."""
    return w._add(page, plan_, DOMAIN)


def change_step(page, plan_):
    """The update and delete page step for DOMAIN."""
    return w._change(page, plan_, DOMAIN)


class FakeLocator:
    def __init__(self, page, selector):
        self.page = page
        self.selector = selector

    def count(self):
        return self.page.count_of(self.selector)

    def nth(self, i):
        return FakeLocator(self.page, f"{self.selector}#{i}")

    def inner_text(self, **kw):
        return self.page.texts.get(self.selector, "")

    def all_inner_texts(self):
        return self.page.lists.get(self.selector, [])

    @property
    def first(self):
        return FakeLocator(self.page, f"{self.selector}#first")

    def is_checked(self, **kw):
        return self.selector in self.page.checked

    def is_enabled(self, **kw):
        return self.selector not in self.page.disabled

    def input_value(self, **kw):
        return self.page.current.get(self.selector, "")

    def click(self, **kw):
        self.page.events.append(("click", self.selector))

    def fill(self, value, **kw):
        self.page.events.append(("fill", self.selector, value))

    def set_checked(self, value, **kw):
        self.page.events.append(("check", self.selector, value))

    def select_option(self, value=None, **kw):
        chosen = value or kw.get("label")
        if self.selector.endswith("select[name=type]"):
            self.page.selected_type = chosen
        self.page.events.append(("select", self.selector, chosen))


class FakePage:
    """Records every action. Selectors count 1 unless listed in ``counts``, or unless they hold
    an ``absent`` token (default: the confirm-prompt selectors), which count 0. The add form's settle
    reads answer with the schema table's fields for the type last selected."""

    def __init__(self, counts=None, texts=None, lists=None, absent=("btn-warning", "warn_"),
                 disabled=(), checked=(), current=None):
        self.disabled = set(disabled)
        self.checked = set(checked)
        self.counts = counts or {}
        self.texts = texts or {}
        self.lists = lists or {}
        self.current = current or {}
        self.absent = absent
        self.events = []
        self.selected_type = None

    def clicks(self):
        return [e[1] for e in self.events if e[0] == "click"]

    def goto(self, url, **kw):
        self.events.append(("goto", url))

    def wait_for_timeout(self, ms):
        pass

    def wait_for_selector(self, selector, **kw):
        pass

    def evaluate(self, js):
        if js == s.CAPTURE_FIELDS_JS:
            return TABLE.get(self.selected_type or "", [{"name": "none"}])
        if js == s.SELECTED_TYPE_JS:
            return self.selected_type
        raise AssertionError("unexpected page script in a write test")

    def locator(self, selector):
        return FakeLocator(self, selector)

    def count_of(self, selector):
        if selector in self.counts:
            return self.counts[selector]
        if any(token in selector for token in self.absent):
            return 0
        return 1


def add_page(extra=None, **kw):
    counts = {ADD_BUTTON: 2, **(extra or {})}
    texts = {f"{ADD_BUTTON}#0": "Add Domain", f"{ADD_BUTTON}#1": "ADD RECORD"}
    return FakePage(counts=counts, texts=texts, **kw)


def runner_for(page):
    return lambda do: do(page)


def reads(monkeypatch, *sequence):
    """The domain opens as DOMAIN without a page. Each read of the open editor (the first read of a run,
    then the post-write re-read) returns the next page list in ``sequence``. The type's schema is the table's."""
    seq = list(sequence)
    monkeypatch.setattr(w, "open_domain", lambda page, domain="": DOMAIN)
    monkeypatch.setattr(w, "read_open_pages", lambda page: seq.pop(0))
    monkeypatch.setattr(w, "read_pages", lambda page, domain="": seq.pop(0))
    monkeypatch.setattr(w, "schema_open", fake_schema_open)


def fake_dig(monkeypatch, stdout=""):
    calls = []

    def run(args, **kw):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(w.subprocess, "run", run)
    return calls


def fake_dig_by_kind(monkeypatch, ns="", a=""):
    """A dig fake that answers an NS query with ``ns`` and every other query with ``a``."""
    calls = []

    def run(args, **kw):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout=ns if "NS" in args else a, stderr="")

    monkeypatch.setattr(w.subprocess, "run", run)
    return calls


class ListPage(FakePage):
    """A page the account's domain list and the DNS editor answer, as ``open_domain`` reads them:
    the list's links, the editor's selected domain (the one in the last ``index.php?LOGIN=`` URL) and a
    saved DNS page for every read."""

    def __init__(self, names, **kw):
        super().__init__(**kw)
        self.names = list(names)
        self.selected = None

    def goto(self, url, **kw):
        super().goto(url, **kw)
        if "index.php?LOGIN=" in url:
            self.selected = url.split("LOGIN=", 1)[1]

    def wait_for_function(self, expression, timeout=None):
        pass

    def wait_for_selector(self, selector, timeout=None):
        pass

    def content(self):
        # One page whose Total (9) is not its row count (4): read as incomplete, with no pagination click.
        return _page(BASE, total=9)

    def evaluate(self, js):
        if js == s.DOMAIN_LIST_JS:
            return {"logins": [name for name in self.names for _ in (0, 1)], "total": len(self.names)}
        if js == s.EDITOR_SELECTED_JS:
            return self.selected
        raise AssertionError("unexpected page script in a domain test")


def editor_goto_urls(page):
    return [event[1] for event in page.events if event[0] == "goto" and "index.php?LOGIN=" in event[1]]


def plan(action, rows=ROWS, **kw):
    """The plan for DOMAIN; add and update get the schema of the requested type, delete none."""
    schema = None if action == "delete" else schema_for(kw["type_"])
    return w.plan_write(action, rows, domain=DOMAIN, schema=schema, **kw)


BASE_ROWS = w._rows(pages_of(BASE))


# --- Plan layer ------------------------------------------------------------------------------

ZONE_WIDE_TYPES = ["NS", "DYN", "SOA"]


def zone_wide_schema(type_):
    """A schema whose type list offers NS, DYN and SOA beside the table's types; the form is the A form."""
    return {"type_names": list(TABLE) + ZONE_WIDE_TYPES, "fields": TABLE["A"], "ttl_options": TTL_LABELS}


@pytest.mark.parametrize("type_", ZONE_WIDE_TYPES)
def test_zone_wide_types_are_planned_like_any_other_type(type_):
    rows = BASE_ROWS + w._rows(pages_of([_row(type_, "www", "old.example.net.", "z1")]))
    schema = zone_wide_schema(type_)
    kw = dict(type_=type_, host="www", domain=DOMAIN)
    added = w.plan_write("add", BASE_ROWS, content="new.example.net.", schema=schema, **kw)
    updated = w.plan_write("update", rows, expect="old.example.net.", content="new.example.net.",
                           schema=schema, **kw)
    deleted = w.plan_write("delete", rows, expect="old.example.net.", **kw)
    assert "refused" not in added and added["type"] == type_
    assert "refused" not in updated and updated["target"]["type"] == type_
    assert "refused" not in deleted and deleted["target"]["type"] == type_


@pytest.mark.parametrize("type_", ZONE_WIDE_TYPES)
def test_a_zone_wide_type_the_schema_does_not_offer_is_bad_type(type_):
    assert plan("add", type_=type_, host="www", content="x") == {"refused": "bad_type"}


@pytest.mark.parametrize("type_", ["SRV", "", "URL"])
def test_add_refuses_a_type_the_schema_does_not_offer(type_):
    assert plan("add", type_=type_, host="www", content="1.2.3.4") == {"refused": "bad_type"}


def test_type_names_match_without_case_and_take_the_schema_spelling():
    assert plan("add", type_="a", host="www", content="1.2.3.4")["type"] == "A"
    assert plan("delete", type_="cname", host="home", expect="target.example.net.")["target"]["type"] == "CNAME"


@pytest.mark.parametrize("host", ["www.example.com", "example.com", "a b", "", ".x", "x.",
                                  "x..y", "a/b", "x?"])
def test_refuses_invalid_hosts(host):
    assert plan("add", type_="A", host=host, content="1.2.3.4") == {"refused": "bad_host"}


def test_host_is_lowercased_and_add_plans_one_row():
    result = plan("add", type_="A", host="WWW", content="1.2.3.4", ttl="1 hour")
    assert result["host"] == "www"
    assert result["after"] == {"type": "A", "host": "www", "content": "1.2.3.4",
                               "ttl": "1 hour", "prio": ""}
    assert result["before"] == [] and result["target"] is None


@pytest.mark.parametrize("action,kw", [
    ("add", {"content": ""}),
    ("update", {"expect": "", "content": "x"}),
    ("update", {"expect": "target.example.net.", "content": ""}),
    ("delete", {"expect": ""}),
])
def test_empty_content_refused(action, kw):
    assert plan(action, type_="A", host="www", **kw) == {"refused": "empty_content"}


def test_apex_a_is_planned_like_any_other_record():
    rows = BASE_ROWS + w._rows(pages_of([_row("A", "@", "1.2.3.4", "a9")]))
    added = plan("add", BASE_ROWS, type_="A", host="@", content="1.2.3.4")
    updated = plan("update", rows, type_="A", host="@", expect="1.2.3.4", content="5.6.7.8")
    deleted = plan("delete", rows, type_="A", host="@", expect="1.2.3.4")
    assert "refused" not in added and added["host"] == "@"
    assert "refused" not in updated and updated["target"]["host"] == "@"
    assert "refused" not in deleted and deleted["target"]["host"] == "@"


def test_apex_caa_is_planned_not_refused():
    result = plan("update", type_="CAA", host="@", expect="0 issue letsencrypt.org",
                  content="0 issue sectigo.com")
    assert result["target"]["host"] == "@" and result["target"]["type"] == "CAA"


def test_a_further_row_of_an_existing_host_and_type_is_planned_with_the_old_row_as_before():
    rows = [_dict("TXT", "www", "v=x", "ht")]
    planned = plan("add", rows, type_="TXT", host="www", content="v=y")
    assert "refused" not in planned and planned["after"]["content"] == "v=y"
    assert [r["content"] for r in planned["before"]] == ["v=x"]


def test_cname_conflicts_both_directions():
    assert plan("add", type_="A", host="home", content="1.2.3.4") == {"refused": "cname_conflict"}
    assert plan("add", type_="TXT", host="home", content="v=x") == {"refused": "cname_conflict"}
    assert plan("add", type_="CNAME", host="@",
                content="x.example.") == {"refused": "cname_conflict"}
    assert plan("add", type_="CNAME", host="newname", content="x.example.")["action"] == "add"


def test_caa_content_must_split_into_three_parts():
    assert plan("add", type_="CAA", host="www", content="0 issue") == {"refused": "bad_caa"}
    assert plan("add", type_="CAA", host="www",
                content="0 issue letsencrypt.org")["action"] == "add"


def test_mx_needs_numeric_prio_and_other_types_refuse_prio():
    assert plan("add", type_="MX", host="mx", content="mail.example.") == {"refused": "bad_prio"}
    assert plan("add", type_="MX", host="mx", content="mail.example.",
                prio="ten") == {"refused": "bad_prio"}
    assert plan("add", type_="A", host="www", content="1.2.3.4",
                prio="10") == {"refused": "bad_prio"}
    assert plan("add", type_="MX", host="mx", content="mail.example.",
                prio="10")["after"]["prio"] == "10"


def test_not_found():
    assert plan("delete", type_="CNAME", host="nosuch", expect="x") == {"refused": "not_found"}


def test_content_mismatch_on_one_character_difference():
    assert plan("delete", type_="CNAME", host="home",
                expect="target.example.net") == {"refused": "content_mismatch"}
    assert plan("update", type_="CNAME", host="home", expect="target.example.neh.",
                content="x.example.") == {"refused": "content_mismatch"}


def test_ambiguous_when_two_rows_both_match_expect():
    rows = [_dict("CNAME", "dup", "x", "hx"), _dict("CNAME", "dup", "x", "hy")]
    assert plan("delete", rows, type_="CNAME", host="dup",
                expect="x") == {"refused": "ambiguous"}


def test_two_rows_with_one_exact_match_target_that_row():
    rows = [_dict("CNAME", "dup", "x", "hx"), _dict("CNAME", "dup", "y", "hy")]
    result = plan("delete", rows, type_="CNAME", host="dup", expect="y")
    assert result["target"]["hash"] == "hy"
    assert len(result["before"]) == 2


def test_update_no_change_refused_and_ttl_is_a_change():
    assert plan("update", type_="CNAME", host="home", expect="target.example.net.",
                content="target.example.net.") == {"refused": "no_change"}
    result = plan("update", type_="CNAME", host="home", expect="target.example.net.",
                  content="target.example.net.", ttl="1 hour")
    assert result["target"]["hash"] == HOME_HASH and result["after"]["ttl"] == "1 hour"


def test_delete_plans_the_exact_fixture_row():
    result = plan("delete", type_="CNAME", host="meet", expect="target.example.net.")
    assert result["target"]["hash"] == MEET_HASH and result["after"] is None


# --- Verification against a panel re-read ----------------------------------------------------

def test_verify_add_needs_exactly_one_row_with_the_requested_ttl():
    add = plan("add", BASE_ROWS, type_="A", host="www", content="1.2.3.4", ttl="1 hour")
    good = pages_of(BASE + [_row("A", "www", "1.2.3.4", "h9", ttl="1 hour")])
    assert w.verify(add, good) == []
    assert w.verify(add, pages_of(BASE))
    assert w.verify(add, pages_of(BASE + [_row("A", "www", "1.2.3.4", "h9")])) == [
        "ttl not shown as requested"]


def test_verify_delete_and_incomplete_reread():
    delete = plan("delete", BASE_ROWS, type_="CNAME", host="meet", expect="target.example.net.")
    assert w.verify(delete, pages_of(BASE_NO_MEET)) == []
    assert w.verify(delete, pages_of(BASE))
    assert any("incomplete" in d for d in w.verify(delete, [_page(BASE_NO_MEET, total=9)]))


def test_verify_update_needs_old_gone_and_new_present():
    upd = plan("update", BASE_ROWS, type_="CNAME", host="home", expect="target.example.net.",
               content="new.example.")
    assert w.verify(upd, pages_of(AFTER_UPDATE)) == []
    assert w.verify(upd, pages_of(BASE))


# --- Page actions (recording fake) -----------------------------------------------------------

def test_add_clicks_add_then_save_and_nothing_else():
    page = add_page()
    add_step(page, plan("add", type_="A", host="www", content="1.2.3.4"))
    assert [e[0] for e in page.events] == ["goto", "click", "select", "fill", "fill", "click"]
    assert page.clicks() == [f"{ADD_BUTTON}#1", f"{ADD_FORM} button[type=submit].btn-success:visible"]
    assert ("fill", f"{ADD_FORM} input[name=content]", "1.2.3.4") in page.events


def test_visible_confirm_in_add_form_aborts_before_save():
    page = add_page(absent=())
    with pytest.raises(w.PanelRefusal):
        add_step(page, plan("add", type_="A", host="www", content="1.2.3.4"))
    assert page.clicks() == [f"{ADD_BUTTON}#1"]


def test_ttl_label_is_selected_or_raised_when_absent():
    page = add_page(lists={f"{ADD_FORM} select[name=ttl] option": ["[DEF] 2 hours", "1 hour"]})
    add_step(page, plan("add", type_="A", host="www", content="1.2.3.4", ttl="1 hour"))
    assert ("select", f"{ADD_FORM} select[name=ttl]", "1 hour") in page.events
    with pytest.raises(w.WriteStepError) as caught:
        add_step(add_page(lists={f"{ADD_FORM} select[name=ttl] option": ["[DEF] 2 hours"]}),
               plan("add", type_="A", host="www", content="1.2.3.4", ttl="1 hour"))
    assert caught.value.step == "ttl_option"


def test_delete_clicks_only_the_planned_rows_delete_button_on_its_page():
    rows = [dict(r, page=2) if r["host"] == "meet" else dict(r, page=1) for r in ROWS]
    page = FakePage()
    change_step(page, plan("delete", rows, type_="CNAME", host="meet", expect="target.example.net."))
    row = f"div.item-wrapped[data-hash='{MEET_HASH}']"
    assert page.clicks() == [
        w._ROW_PAGE_LINK.format(2) + "#first",
        f"{row} button.btn-edit:visible",
        f"{row} form[name=formEditRecord]:visible button.btn-danger:visible:has-text('Delete')",
    ]
    assert not [e for e in page.events if e[0] == "fill"]


def test_update_fills_only_the_changed_content_and_saves_once():
    page = FakePage()
    change_step(page, plan("update", type_="CNAME", host="home", expect="target.example.net.",
                         content="new.example."))
    row = f"div.item-wrapped[data-hash='{HOME_HASH}']"
    edit = f"{row} form[name=formEditRecord]:visible"
    assert page.clicks() == [f"{row} button.btn-edit:visible", f"{edit} button.btn-success:visible"]
    assert [e for e in page.events if e[0] == "fill"] == [
        ("fill", f"{edit} input[name=content]", "new.example.")]


# --- Orchestration (fake runner, monkeypatched reads and dig) --------------------------------

def test_preview_clicks_nothing_and_returns_the_plan(monkeypatch):
    reads(monkeypatch, pages_of(BASE))
    page = add_page()
    result = t.record_add("A", "www", "1.2.3.4", runner=runner_for(page))
    assert result["ok"] is True and result["confirmed"] is False
    assert result["after"]["host"] == "www"
    assert result["domain"] == DOMAIN
    assert page.events == []


def test_refusal_clicks_nothing(monkeypatch):
    reads(monkeypatch, pages_of(BASE))
    page = add_page()
    result = t.record_add("A", "home", "1.2.3.4", confirmed=True, runner=runner_for(page))
    assert result == {"ok": False, "action": "add", "refused": "cname_conflict", "domain": DOMAIN}
    assert page.events == []


@pytest.mark.parametrize("pages, reason", [
    ([_page(BASE, total=9)], "incomplete_read"),
])
def test_bulk_or_incomplete_read_refuses_before_any_click(monkeypatch, pages, reason):
    reads(monkeypatch, pages)
    page = add_page()
    result = t.record_add("A", "www", "1.2.3.4", confirmed=True, runner=runner_for(page))
    assert result == {"ok": False, "refused": reason, "domain": DOMAIN}
    assert page.events == []


def test_verified_add_carries_dns_readback(monkeypatch):
    reads(monkeypatch, pages_of(BASE), pages_of(BASE + [_row("A", "www", "1.2.3.4", "h9")]))
    calls = fake_dig(monkeypatch, stdout="1.2.3.4\n")
    result = t.record_add("A", "www", "1.2.3.4", confirmed=True, runner=runner_for(add_page()))
    assert result["ok"] is True and result["verified"] is True and result["panel_verified"] is True
    assert result["dns_matches"] == {"ns19.zoneedit.com": True, "ns8.zoneedit.com": True}
    assert result["dns_readback"]["ns19.zoneedit.com"]["lines"] == ["1.2.3.4"]
    assert calls[0] == ["dig", "+short", "+time=3", "+tries=1", "@ns19.zoneedit.com",
                        "www.example.com", "A"]


def test_verified_update_and_delete(monkeypatch):
    reads(monkeypatch, pages_of(BASE), pages_of(AFTER_UPDATE))
    fake_dig(monkeypatch, stdout="new.example.\n")
    upd = t.record_update("CNAME", "home", "target.example.net.", "new.example.", confirmed=True,
                          runner=runner_for(FakePage()))
    assert upd["ok"] is True and upd["dns_matches"] == {"ns19.zoneedit.com": True,
                                                        "ns8.zoneedit.com": True}

    reads(monkeypatch, pages_of(BASE), pages_of(BASE_NO_MEET))
    fake_dig(monkeypatch, stdout="")
    dele = t.record_delete("CNAME", "meet", "target.example.net.", confirmed=True,
                           runner=runner_for(FakePage()))
    assert dele["ok"] is True and dele["dns_matches"] == {"ns19.zoneedit.com": True,
                                                          "ns8.zoneedit.com": True}


def test_unverified_write_returns_ok_false_and_no_dns(monkeypatch):
    reads(monkeypatch, pages_of(BASE), pages_of(BASE))
    calls = fake_dig(monkeypatch)
    result = t.record_add("A", "www", "1.2.3.4", confirmed=True, runner=runner_for(add_page()))
    assert result["ok"] is False and result["panel_verified"] is False
    assert result["differences"] and "dns_readback" not in result
    assert calls == []


def test_missing_dig_does_not_fail_a_verified_write(monkeypatch):
    reads(monkeypatch, pages_of(BASE), pages_of(BASE + [_row("A", "www", "1.2.3.4", "h9")]))

    def missing(args, **kw):
        raise FileNotFoundError("dig")

    monkeypatch.setattr(w.subprocess, "run", missing)
    result = t.record_add("A", "www", "1.2.3.4", confirmed=True, runner=runner_for(add_page()))
    assert result["ok"] is True
    assert result["dns_readback"] == {"error": "dig_unavailable"}
    assert result["dns_matches"] == {}


def test_step_failure_names_the_step_only(monkeypatch):
    reads(monkeypatch, pages_of(BASE))
    page = add_page(extra={f"{ADD_FORM} select[name=type]": 0})
    result = t.record_add("A", "www", "1.2.3.4", confirmed=True, runner=runner_for(page))
    assert result["ok"] is False
    assert result["refused"] == "step_failed" and result["step"] == "add_type"


# --- Server surface --------------------------------------------------------------------------

def _annotation(annotations, key):
    return annotations.get(key) if isinstance(annotations, dict) else getattr(annotations, key)


WRITE_EXPECT = {
    "zoneedit_record_add": ("ZoneEdit Add Record", False),
    "zoneedit_record_update": ("ZoneEdit Update Record", True),
    "zoneedit_record_delete": ("ZoneEdit Delete Record", True),
}


def test_nine_tools_listed_with_write_annotations():
    tools = {tool.name: tool for tool in asyncio.run(srv.mcp.list_tools())}
    assert set(tools) == {"zoneedit_records", "zoneedit_selftest", "zoneedit_2fa_status",
                          "zoneedit_domains", "zoneedit_schema",
                          "zoneedit_2fa_latch_clear", *WRITE_EXPECT}
    titles = []
    for name, (title, destructive) in WRITE_EXPECT.items():
        annotations = tools[name].annotations
        titles.append(_annotation(annotations, "title"))
        assert _annotation(annotations, "title") == title
        assert _annotation(annotations, "readOnlyHint") is False
        assert _annotation(annotations, "destructiveHint") is destructive
        assert _annotation(annotations, "idempotentHint") is False
        assert _annotation(annotations, "openWorldHint") is True
    for name in ("zoneedit_records", "zoneedit_selftest", "zoneedit_2fa_status",
                 "zoneedit_domains", "zoneedit_schema"):
        titles.append(_annotation(tools[name].annotations, "title"))
        assert _annotation(tools[name].annotations, "readOnlyHint") is True
        assert _annotation(tools[name].annotations, "title").startswith("ZoneEdit ")
    titles.append(_annotation(tools["zoneedit_2fa_latch_clear"].annotations, "title"))
    assert _annotation(tools["zoneedit_2fa_latch_clear"].annotations, "readOnlyHint") is False
    assert len(set(titles)) == 9


def test_write_tool_without_bearer_is_refused_before_the_runner(monkeypatch):
    monkeypatch.delenv("ZONEEDIT_TRANSPORT", raising=False)
    called = []

    def runner(*args, **kwargs):
        called.append(True)
        raise RuntimeError("runner must not be reached")

    monkeypatch.setattr(s, "run", runner)
    with pytest.raises(ToolError):
        asyncio.run(srv.mcp.call_tool("zoneedit_record_add",
                                      {"type": "A", "host": "www", "content": "1.2.3.4"}))
    assert called == []


# --- Fixes from main-agent review round 1 ----------------------------------------------------

FLAG = f"{ADD_FORM} input[name=flag]"


def test_caa_add_selects_tag_and_provider_and_fills_flag():
    page = add_page()
    add_step(page, plan("add", type_="CAA", host="www", content="0 issue letsencrypt.org"))
    assert ("select", f"{ADD_FORM} select[name=tag]", "issue") in page.events
    assert ("select", f"{ADD_FORM} select[name=provider]", "letsencrypt.org") in page.events
    assert ("fill", FLAG, "0") in page.events
    assert not [e for e in page.events if e[0] == "fill" and "tag" in e[1]]


def test_missing_caa_option_stops_before_selecting():
    page = add_page(extra={f'{ADD_FORM} select[name=provider] option[value="letsencrypt.org"]': 0})
    with pytest.raises(w.WriteStepError) as caught:
        add_step(page, plan("add", type_="CAA", host="www", content="0 issue letsencrypt.org"))
    assert caught.value.step == "caa_provider"
    assert not [e for e in page.events if e[0] == "select" and "provider" in e[1]]


CAA_ROW = f"div.item-wrapped[data-hash='65e3f174cd4ca4152c4074c18d628ec7']"
CAA_EDIT_FLAG = f"{CAA_ROW} form[name=formEditRecord]:visible input[name=flag]"
ADD_FLAG = f"{ADD_FORM} input[name=flag]"


def test_disabled_caa_flag_on_edit_with_the_default_value_is_skipped():
    page = FakePage(disabled=(CAA_EDIT_FLAG,), current={CAA_EDIT_FLAG: "0"})
    change_step(page, plan("update", BASE_ROWS, type_="CAA", host="@", expect="0 issue letsencrypt.org",
                           content="0 issue sectigo.com"))
    assert not [e for e in page.events if e[0] == "fill" and e[1] == CAA_EDIT_FLAG]
    assert ("select", f"{CAA_ROW} form[name=formEditRecord]:visible select[name=provider]",
            "sectigo.com") in page.events


def test_disabled_caa_flag_on_edit_with_another_value_is_refused_by_the_plan():
    assert plan("update", BASE_ROWS, type_="CAA", host="@", expect="0 issue letsencrypt.org",
                content="1 issuewild letsencrypt.org") == {"refused": "field_disabled"}


def test_disabled_caa_flag_on_edit_with_another_value_raises_at_the_page_step_before_any_click():
    page = FakePage(disabled=(CAA_EDIT_FLAG,), current={CAA_EDIT_FLAG: "0"})
    planned = plan("update", BASE_ROWS, type_="CAA", host="@", expect="0 issue letsencrypt.org",
                   content="0 issue sectigo.com")
    planned["values"]["flag"] = "1"
    with pytest.raises(w.WriteStepError) as caught:
        change_step(page, planned)
    assert caught.value.step == "field_disabled"
    assert page.clicks() == [f"{CAA_ROW} button.btn-edit:visible"]


def test_disabled_caa_flag_on_add_plans_the_legacy_value_and_skips_the_fill():
    page = add_page(disabled=(ADD_FLAG,))
    add_step(page, plan("add", type_="CAA", host="www", content="0 issue letsencrypt.org"))
    assert not [e for e in page.events if e[0] == "fill" and e[1] == ADD_FLAG]
    assert ("select", f"{ADD_FORM} select[name=tag]", "issue") in page.events
    assert page.clicks()[-1] == SAVE_ADD


def test_disabled_caa_flag_on_add_with_another_value_is_refused_by_the_plan():
    assert plan("add", type_="CAA", host="www", content="1 issue letsencrypt.org") == {"refused": "field_disabled"}


def test_disabled_caa_flag_on_add_with_another_value_raises_at_the_page_step_before_save():
    page = add_page(disabled=(ADD_FLAG,))
    planned = plan("add", type_="CAA", host="www", content="0 issue letsencrypt.org")
    planned["values"]["flag"] = "1"
    with pytest.raises(w.WriteStepError) as caught:
        add_step(page, planned)
    assert caught.value.step == "field_disabled"
    assert page.clicks() == [f"{ADD_BUTTON}#1"]


def test_disabled_field_with_an_empty_placeholder_refuses_any_value():
    schema = {"type_names": ["CAA"], "ttl_options": TTL_LABELS,
              "fields": [dict(f, placeholder="") if f["name"] == "flag" else f for f in TABLE["CAA"]]}
    assert w.plan_write("add", [], type_="CAA", host="www", domain=DOMAIN, schema=schema,
                        content="0 issue letsencrypt.org") == {"refused": "field_disabled"}


def test_locator_matching_two_elements_stops_before_the_edit_click():
    row = f"div.item-wrapped[data-hash='{HOME_HASH}']"
    page = FakePage(counts={f"{row} button.btn-edit:visible": 2})
    with pytest.raises(w.WriteStepError) as caught:
        change_step(page, plan("update", type_="CNAME", host="home",
                             expect="target.example.net.", content="new.example."))
    assert caught.value.step == "edit_button"
    assert page.clicks() == []


def test_delete_button_matching_two_stops_without_the_delete_click():
    row = f"div.item-wrapped[data-hash='{MEET_HASH}']"
    edit = f"{row} form[name=formEditRecord]:visible"
    page = FakePage(counts={f"{edit} button.btn-danger:visible:has-text('Delete')": 2})
    with pytest.raises(w.WriteStepError) as caught:
        change_step(page, plan("delete", type_="CNAME", host="meet", expect="target.example.net."))
    assert caught.value.step == "delete_button"
    assert page.clicks() == [f"{row} button.btn-edit:visible"]


def test_verify_update_names_the_old_row_still_present():
    upd = plan("update", type_="CNAME", host="home", expect="target.example.net.",
               content="new.example.")
    diffs = w.verify(upd, pages_of(BASE + [_row("CNAME", "home", "new.example.", "h9")]))
    assert "old row still present after update" in diffs


def test_row_hash_must_be_hex_and_no_selector_is_built():
    with pytest.raises(w.WriteStepError) as caught:
        w._row_scope("x'] or 1=1 //")
    assert caught.value.step == "row_hash"
    page = FakePage()
    bad = plan("delete", type_="CNAME", host="meet", expect="target.example.net.")
    bad["target"] = dict(bad["target"], hash="x'] or 1=1 //")
    with pytest.raises(w.WriteStepError):
        change_step(page, bad)
    assert page.events == []


def test_cname_and_mx_targets_get_the_trailing_dot_in_the_plan():
    add = plan("add", type_="CNAME", host="newname", content="host.example.com")
    assert add["content"] == "host.example.com." and add["after"]["content"] == "host.example.com."
    mx = plan("add", type_="MX", host="mx", content="mail.example.com", prio="10")
    assert mx["content"] == "mail.example.com."
    upd = plan("update", type_="CNAME", host="home", expect="target.example.net.",
               content="new.example")
    assert upd["content"] == "new.example." and upd["after"]["content"] == "new.example."


def test_preview_shows_the_dotted_value(monkeypatch):
    reads(monkeypatch, pages_of(BASE))
    result = t.record_add("CNAME", "newname", "host.example.com", runner=runner_for(add_page()))
    assert result["after"]["content"] == "host.example.com."


def test_txt_a_and_caa_values_are_never_given_a_trailing_dot():
    cases = [
        plan("add", type_="TXT", host="www", content="v=spf1 -all"),
        plan("add", type_="A", host="www", content="192.0.2.7"),
        plan("add", type_="CAA", host="www", content="0 issue letsencrypt.org"),
        plan("update", [_dict("TXT", "txt", "v=old", "ht")], type_="TXT", host="txt",
             expect="v=old", content="v=spf1 -all"),
    ]
    expected = ["v=spf1 -all", "192.0.2.7", "0 issue letsencrypt.org", "v=spf1 -all"]
    for result, value in zip(cases, expected):
        assert result["content"] == value and result["after"]["content"] == value


# --- Live state, pending rows, pagination and unknown outcome -------------------------------

BULK = "#editor_bulk_save_mode"
UNKNOWN = "the change may be live; read the zone before retrying"
SAVE_ADD = f"{ADD_FORM} button[type=submit].btn-success:visible"


class PromptAfterSave(FakePage):
    """The replace prompt appears only once the Save click has happened."""

    def count_of(self, selector):
        last = self.events[-1] if self.events else None
        if last and last[0] == "click" and "btn-success" in last[1] and "btn-warning" in selector:
            return 1
        return super().count_of(selector)


def test_read_bulk_save_off_reads_the_live_checked_state():
    assert s.read_bulk_save_off(FakePage()) is True
    assert s.read_bulk_save_off(FakePage(checked=(BULK,))) is False
    assert s.read_bulk_save_off(FakePage(counts={BULK: 0})) is None
    assert s.read_bulk_save_off(FakePage(counts={BULK: 2})) is None


def test_selftest_reports_the_live_bulk_value():
    assert t.selftest(runner=lambda read: (FIXTURE, False, DOMAIN))["bulk_save_off"] is False


@pytest.mark.parametrize("make", [
    lambda: add_page(checked=(BULK,)),
    lambda: add_page(extra={BULK: 0}),
    lambda: add_page(extra={BULK: 2}),
])
def test_bulk_save_not_off_refuses_before_any_click(monkeypatch, make):
    reads(monkeypatch, pages_of(BASE))
    page = make()
    result = t.record_add("A", "www", "1.2.3.4", confirmed=True, runner=runner_for(page))
    assert result == {"ok": False, "refused": "bulk_save_on_or_unknown", "domain": DOMAIN}
    assert page.events == []


def test_verify_rejects_a_pending_add_update_and_delete():
    add = plan("add", BASE_ROWS, type_="A", host="www", content="1.2.3.4")
    assert any("pending" in d for d in w.verify(
        add, pages_of(BASE + [_row("A", "www", "1.2.3.4", "h9", pending=True)])))
    upd = plan("update", BASE_ROWS, type_="CNAME", host="home", expect="target.example.net.",
               content="new.example.")
    rows = [_row("CNAME", "home", "new.example.", "h9", pending=True)] + BASE[1:]
    assert any("pending" in d for d in w.verify(upd, pages_of(rows)))
    delete = plan("delete", BASE_ROWS, type_="CNAME", host="meet", expect="target.example.net.")
    rows = BASE_NO_MEET + [_row("CNAME", "meet", "target.example.net.", MEET_HASH, pending=True)]
    assert any("pending" in d for d in w.verify(delete, pages_of(rows)))


def test_fixture_with_one_icon_shown_is_rejected_by_verify():
    shown = FIXTURE.replace('style="display: none;" aria-label="Queued record"',
                            'aria-label="Queued record"', 1)
    rows = [r for r in ROWS if not (r["type"] == "CAA" and r["host"] == "@")]
    add = plan("add", rows, type_="CAA", host="@", content="0 issue letsencrypt.org")
    assert any("pending" in d for d in w.verify(add, [shown]))


def test_pagination_clicks_only_the_first_visible_link_when_two_match():
    sel = w._ROW_PAGE_LINK.format(2)
    page = FakePage(counts={sel: 2})
    w._goto_dns(page, DOMAIN, 2)
    assert page.clicks() == [f"{sel}#first"]


def test_pagination_with_no_visible_link_stops_before_any_click():
    page = FakePage(counts={w._ROW_PAGE_LINK.format(2): 0})
    with pytest.raises(w.WriteStepError) as caught:
        w._goto_dns(page, DOMAIN, 2)
    assert caught.value.step == "pagination"
    assert page.clicks() == []


def test_replace_prompt_before_the_save_click_is_still_a_refusal(monkeypatch):
    reads(monkeypatch, pages_of(BASE))
    page = add_page(absent=())
    result = t.record_add("A", "www", "1.2.3.4", confirmed=True, runner=runner_for(page))
    assert result["refused"] == "replace_prompt_shown"
    assert "outcome" not in result
    assert page.clicks() == [f"{ADD_BUTTON}#1"]


def test_replace_prompt_after_the_save_click_is_outcome_unknown(monkeypatch):
    reads(monkeypatch, pages_of(BASE))
    page = PromptAfterSave(counts={ADD_BUTTON: 2},
                           texts={f"{ADD_BUTTON}#0": "Add Domain", f"{ADD_BUTTON}#1": "ADD RECORD"})
    result = t.record_add("A", "www", "1.2.3.4", confirmed=True, runner=runner_for(page))
    assert result["outcome"] == "unknown" and result["ok"] is False
    assert result["confirmed"] is True and result["message"] == UNKNOWN
    assert result["error_type"] == "PanelRefusal"
    assert "refused" not in result
    assert page.clicks()[-1] == SAVE_ADD


def test_reread_raising_after_the_final_click_is_outcome_unknown(monkeypatch):
    reads(monkeypatch, pages_of(BASE))

    def reread(page, domain=""):
        raise RuntimeError("boom")

    monkeypatch.setattr(w, "read_pages", reread)
    result = t.record_add("A", "www", "1.2.3.4", confirmed=True, runner=runner_for(add_page()))
    assert result["outcome"] == "unknown" and result["ok"] is False
    assert result["error_type"] == "RuntimeError" and result["message"] == UNKNOWN


def test_step_error_after_the_final_click_is_outcome_unknown(monkeypatch):
    reads(monkeypatch, pages_of(BASE))

    def perform(page, plan, state, domain):
        state["final_clicked"] = True
        raise w.WriteStepError("delete_button")

    monkeypatch.setattr(w, "_perform", perform)
    result = t.record_add("A", "www", "1.2.3.4", confirmed=True, runner=runner_for(add_page()))
    assert result["outcome"] == "unknown" and result["ok"] is False
    assert result["step"] == "delete_button" and result["error_type"] == "WriteStepError"
    assert "refused" not in result


# --- Domain argument: host rules, the editor it opens, and refusals before any click --------------

@pytest.mark.parametrize("host, good", [
    ("@", True), ("www", True), ("x.example.net", True), ("example.net", True), ("example", True),
    ("example.com", False), ("www.example.com", False), ("a.b.example.com", False),
])
def test_valid_host_refuses_the_domain_name_and_its_suffix_only(host, good):
    assert w.valid_host(host, DOMAIN) is good


def test_the_same_name_is_refused_under_its_own_domain_and_allowed_under_another():
    assert w.plan_write("add", [], type_="A", host="example.net", domain="example.net",
                        content="1.2.3.4", schema=schema_for("A")) == {"refused": "bad_host"}
    assert w.plan_write("add", [], type_="A", host="example.net", domain="example.com",
                        content="1.2.3.4", schema=schema_for("A"))["action"] == "add"


def test_plan_write_refuses_suffix_hosts_for_the_domain_it_is_given():
    assert plan("add", type_="A", host="www.example.com", content="1.2.3.4") == {"refused": "bad_host"}
    assert plan("add", type_="A", host="x.example.net", content="1.2.3.4")["action"] == "add"


def test_goto_dns_navigates_the_domain_it_is_given():
    page = FakePage()
    w._goto_dns(page, "example.net")
    assert page.events[0] == ("goto", s.dns_url_for("example.net"))


def _ns_row(host, content, type_="NS"):
    return {"type": type_, "host": host, "content": content}


def test_nameservers_from_rows_takes_apex_ns_rows_once_in_page_order():
    rows = [
        _ns_row("@", "ns8.zoneedit.com"),                    # no trailing dot
        _ns_row("@", "ns19.zoneedit.com."),
        _ns_row("@", "ns19.zoneedit.com."),                 # duplicate
        _ns_row("@", "not a name."),                        # invalid value
        _ns_row("www", "ns.example.net."),                  # NS row below the apex
        _ns_row("@", "ns.example.org.", type_="A"),         # apex row of another type
    ]
    assert w.nameservers_from_rows(rows) == ["ns8.zoneedit.com", "ns19.zoneedit.com"]
    assert w.nameservers_from_rows([]) == []


def test_dns_readback_asks_every_discovered_server(monkeypatch):
    calls = fake_dig(monkeypatch, stdout="1.2.3.4\n")
    names = ["ns1.example.net", "ns2.example.net", "ns3.example.net"]
    readback, matches = w.dns_readback("add", "A", "www", "1.2.3.4", DOMAIN, names)
    assert [call[4] for call in calls] == ["@ns1.example.net", "@ns2.example.net", "@ns3.example.net"]
    assert set(readback) == set(names)
    assert matches == {name: True for name in names}


def test_dns_readback_with_no_name_server_asks_nothing(monkeypatch):
    calls = fake_dig(monkeypatch, stdout="1.2.3.4\n")
    assert w.dns_readback("add", "A", "www", "1.2.3.4", DOMAIN, []) == ({"error": "no_nameservers"}, {})
    assert calls == []


def test_dig_fallback_names_the_servers_when_the_zone_shows_none(monkeypatch):
    reads(monkeypatch, pages_of(BASE_NO_NS), pages_of(BASE_NO_NS + [_row("A", "www", "1.2.3.4", "h9")]))
    calls = fake_dig_by_kind(monkeypatch, ns="ns19.zoneedit.com.\nns8.zoneedit.com.\n", a="1.2.3.4\n")
    result = t.record_add("A", "www", "1.2.3.4", confirmed=True, runner=runner_for(add_page()))
    assert result["ok"] is True
    assert calls[0] == ["dig", "+short", "+time=3", "+tries=1", "NS", DOMAIN]
    assert result["dns_matches"] == {"ns19.zoneedit.com": True, "ns8.zoneedit.com": True}


def test_no_name_server_from_zone_or_dig_gives_no_nameservers(monkeypatch):
    reads(monkeypatch, pages_of(BASE_NO_NS), pages_of(BASE_NO_NS + [_row("A", "www", "1.2.3.4", "h9")]))
    calls = fake_dig_by_kind(monkeypatch, ns="", a="1.2.3.4\n")
    result = t.record_add("A", "www", "1.2.3.4", confirmed=True, runner=runner_for(add_page()))
    assert result["ok"] is True
    assert result["dns_readback"] == {"error": "no_nameservers"}
    assert result["dns_matches"] == {}
    assert [call for call in calls if "NS" in call] == [
        ["dig", "+short", "+time=3", "+tries=1", "NS", DOMAIN]]


@pytest.mark.parametrize("bad", ["EXAMPLE.com", "example.com/", "example", "exa mple.com", "example.com."])
def test_write_refuses_bad_domain_syntax_before_any_browser_run(bad):
    def runner(do):
        raise AssertionError("a bad domain must not reach a browser run")

    result = t.record_add("A", "www", "1.2.3.4", confirmed=True, domain=bad, runner=runner)
    assert result == {"ok": False, "refused": "bad_domain", "domain": None}


def test_write_refuses_an_unknown_domain_before_its_editor_or_any_click():
    page = ListPage(["example.com", "example.net"])
    result = t.record_add("A", "www", "1.2.3.4", confirmed=True, domain="example.org",
                          runner=runner_for(page))
    assert result == {"ok": False, "refused": "unknown_domain", "domains": ["example.com", "example.net"],
                      "domain": None}
    assert editor_goto_urls(page) == []
    assert page.clicks() == []


def test_write_with_several_domains_and_none_named_is_refused_before_any_click():
    page = ListPage(["example.com", "example.net"])
    result = t.record_add("A", "www", "1.2.3.4", confirmed=True, runner=runner_for(page))
    assert result == {"ok": False, "refused": "domain_required", "domains": ["example.com", "example.net"],
                      "domain": None}
    assert editor_goto_urls(page) == []
    assert page.clicks() == []


def test_a_named_domain_opens_its_own_editor_and_reports_its_name():
    page = ListPage(["example.com", "example.net"])
    result = t.record_add("A", "www", "1.2.3.4", confirmed=True, domain="example.net",
                          runner=runner_for(page))
    assert editor_goto_urls(page) == [s.dns_url_for("example.net")]
    assert result == {"ok": False, "refused": "incomplete_read", "domain": "example.net"}
    assert page.clicks() == []


def test_selftest_with_several_domains_and_none_named_opens_the_first_on_the_same_page():
    page = ListPage(["example.com", "example.net"])
    result = t.selftest(runner=lambda read: read(page))
    assert result["login"] == "ok" and result["domain"] == "example.com"
    assert editor_goto_urls(page) == [s.dns_url_for("example.com")]
    assert len([event for event in page.events if event[0] == "goto"]) == 2


def test_selftest_refuses_a_bad_domain_without_a_run():
    def runner(read):
        raise AssertionError("a bad domain must not reach a browser run")

    assert t.selftest("EXAMPLE.com", runner=runner) == {"ok": False, "refused": "bad_domain"}


# --- Schema-driven writes: refusals, values, identifiers, verification, read-back -------------

def _schema(fields, types=("X",)):
    return {"type_names": list(types), "ttl_options": TTL_LABELS, "fields": fields}


SRV_FIELDS = [
    _field("service", "Service", "text", required=True),
    _field("proto", "Protocol", "select", options=["_tcp - Stream", "_udp - Datagram"]),
    _field("host", "Host", "text", required=True),
    _field("prio", "Priority", "text"), _field("weight", "Weight", "text"), _field("port", "Port", "text"),
    _field("content", "Target", "text", required=True),
    _field("enabled", "Enabled", "checkbox"),
    _field("locked", "Locked", "text", disabled=True),
    _TTL,
]
SRV_SCHEMA = {"type_names": ["SRV", "TXT"], "ttl_options": TTL_LABELS, "fields": SRV_FIELDS}


def srv_plan(rows=None, **kw):
    """An add of an SRV record in DOMAIN (the service-style type: host is not exact)."""
    return w.plan_write("add", [] if rows is None else rows, type_="SRV", host="_sip", domain=DOMAIN,
                        schema=SRV_SCHEMA, **kw)


def test_missing_schema_refuses_add_and_update_but_not_delete():
    assert w.plan_write("add", ROWS, type_="A", host="www", domain=DOMAIN,
                        content="1.2.3.4") == {"refused": "schema_unavailable"}
    assert w.plan_write("update", ROWS, type_="A", host="www", domain=DOMAIN, expect="x",
                        content="y") == {"refused": "schema_unavailable"}
    assert "refused" not in w.plan_write("delete", ROWS, type_="CNAME", host="home", domain=DOMAIN,
                                         expect="target.example.net.")


def test_values_come_from_the_legacy_inputs_then_the_fields():
    caa = plan("add", type_="CAA", host="www", content="0 issue letsencrypt.org")
    assert caa["values"] == {"flag": "0", "tag": "issue", "provider": "letsencrypt.org"}
    mx = plan("add", type_="MX", host="mx", content="mail.example.com", prio="10")
    assert mx["values"] == {"content": "mail.example.com.", "prio": "10"}
    txt = plan("add", type_="TXT", host="www", fields={"content": "v=spf1 -all"})
    assert txt["values"] == {"content": "v=spf1 -all"} and txt["content"] == "v=spf1 -all"


@pytest.mark.parametrize("kw, code", [
    (dict(type_="A", host="www", content="1.2.3.4", fields={"content": "x"}), "bad_field"),
    (dict(type_="A", host="www", content="1.2.3.4", fields={"ttl": "1 hour"}), "bad_field"),
    (dict(type_="A", host="www", content="1.2.3.4", fields={"host": "x"}), "bad_field"),
    (dict(type_="A", host="www", content="1.2.3.4", fields={"type": "x"}), "bad_field"),
    (dict(type_="A", host="www", content="1.2.3.4", fields={"nosuch": "x"}), "unknown_field"),
    (dict(type_="A", host="www", content="1.2.3.4", prio="10"), "bad_prio"),
    (dict(type_="CAA", host="www", content="0 issue"), "bad_caa"),
    (dict(type_="A", host="www", content="1.2.3.4", ttl="7 fortnights"), "bad_ttl"),
    (dict(type_="A", host="www", fields={"content": ""}), "empty_content"),
])
def test_add_refusals_for_the_values_and_the_legacy_inputs(kw, code):
    assert plan("add", **kw) == {"refused": code}


def test_select_option_must_match_text_or_the_part_before_dash():
    ok = srv_plan(content="t", fields={"proto": "_tcp", "service": "_sip"})
    assert "refused" not in ok and ok["values"]["proto"] == "_tcp"
    assert "refused" not in srv_plan(content="t", fields={"proto": "_udp - Datagram", "service": "_sip"})
    assert srv_plan(content="t", fields={"proto": "_sctp", "service": "_sip"}) == {"refused": "bad_option"}


def test_checkbox_accepts_true_false_1_0_yes_no_in_any_case_and_no_other_value():
    for value in ("YES", "no", "1", "0", "True"):
        assert "refused" not in srv_plan(content="t", fields={"service": "_sip", "enabled": value})
    assert srv_plan(content="t", fields={"service": "_sip", "enabled": "maybe"}) == {"refused": "bad_option"}


def test_add_refuses_a_disabled_field_the_user_sets():
    assert srv_plan(content="t", fields={"service": "_sip", "locked": "x"}) == {"refused": "field_disabled"}


def test_add_missing_required_field_names_the_fields_and_empty_content_is_its_own_code():
    assert srv_plan(content="t", fields={}) == {"refused": "missing_field", "missing": ["service"]}
    assert srv_plan(fields={"service": "_sip"}) == {"refused": "empty_content"}


def test_ttl_matches_the_label_ignoring_a_non_breaking_space_and_keeps_the_panel_spelling():
    result = plan("add", type_="A", host="www", content="1.2.3.4", ttl="1 week")
    assert result["ttl"] == "1 week"
    assert plan("add", type_="A", host="www", content="1.2.3.4", ttl="")["ttl"] == ""


def test_host_exact_follows_the_host_label_and_the_service_field():
    assert plan("add", type_="A", host="www", content="1.2.3.4")["host_exact"] is True
    selector = {"type_names": ["DKIM"], "ttl_options": TTL_LABELS,
                "fields": [_field("host", "Selector", "text", required=True),
                           _field("content", "Key", "textarea", required=True)]}
    assert w.plan_write("add", [], type_="DKIM", host="s1", domain=DOMAIN, schema=selector,
                        content="k")["host_exact"] is False
    assert srv_plan(content="t", fields={"service": "_sip"})["host_exact"] is False


def test_update_and_delete_match_by_hash_and_both_identifiers_must_agree():
    upd = plan("update", ROWS, type_="CNAME", host="home", expect_hash=HOME_HASH, content="new.example.")
    assert upd["target"]["hash"] == HOME_HASH
    assert plan("update", ROWS, type_="CNAME", host="home", expect_hash="ffffffff",
                content="x.example.") == {"refused": "content_mismatch"}
    assert plan("delete", ROWS, type_="CNAME", host="home", expect_hash=HOME_HASH)["target"]["hash"] == HOME_HASH
    assert plan("delete", ROWS, type_="CNAME", host="home", expect="target.example.net.",
                expect_hash=MEET_HASH) == {"refused": "content_mismatch"}
    assert plan("delete", ROWS, type_="CNAME", host="home", expect_hash="xyz!") == {"refused": "bad_hash"}


def test_update_refusals_for_nothing_to_change_and_an_unknown_field():
    assert plan("update", ROWS, type_="CNAME", host="home", expect="target.example.net.") == {
        "refused": "empty_content"}
    assert plan("update", ROWS, type_="CNAME", host="home", expect="target.example.net.",
                fields={"nosuch": "x"}) == {"refused": "unknown_field"}


def test_verify_add_refuses_two_new_rows_and_a_wrong_type_or_host():
    add = plan("add", BASE_ROWS, type_="A", host="www", content="1.2.3.4")
    assert w.verify(add, pages_of(BASE + [_row("A", "www", "1.2.3.4", "h9"),
                                           _row("A", "www", "5.6.7.8", "h10")])) == [
        "expected exactly one new row, found 2"]
    assert "new row has another type" in w.verify(add, pages_of(BASE + [_row("TXT", "www", "1.2.3.4", "h9")]))
    assert "new row has another host" in w.verify(add, pages_of(BASE + [_row("A", "other", "1.2.3.4", "h9")]))


def test_verify_add_ignores_the_host_when_the_type_is_not_host_exact():
    add = srv_plan(rows=BASE_ROWS, content="t", fields={"service": "_sip"})
    assert w.verify(add, pages_of(BASE + [_row("SRV", "elsewhere", "t", "h9")])) == []


def test_verify_delete_names_a_vanished_neighbour():
    delete = plan("delete", BASE_ROWS, type_="CNAME", host="meet", expect="target.example.net.")
    pages = pages_of([r for r in BASE if ">mail<" not in r and ">meet<" not in r])
    assert any("another row vanished" in d for d in w.verify(delete, pages))


def test_verify_update_names_a_vanished_neighbour_and_refuses_two_new_rows():
    upd = plan("update", BASE_ROWS, type_="CNAME", host="home", expect="target.example.net.",
               content="new.example.")
    without_mail = [r for r in BASE if ">mail<" not in r]
    pages = pages_of([_row("CNAME", "home", "new.example.", HOME_HASH)] + without_mail[1:])
    assert any("another row vanished" in d for d in w.verify(upd, pages))
    two_new = pages_of(BASE + [_row("CNAME", "n1", "x.", "h1"), _row("CNAME", "n2", "y.", "h2")])
    assert "expected at most one new row, found 2" in w.verify(upd, two_new)


def test_readback_with_an_empty_needle_lists_each_servers_lines_and_matches_nothing(monkeypatch):
    fake_dig(monkeypatch, stdout="1.2.3.4\n")
    readback, matches = w.dns_readback("add", "A", "www", "", DOMAIN, ["ns1.example.net"])
    assert readback["ns1.example.net"]["lines"] == ["1.2.3.4"]
    assert matches == {}


def test_a_type_that_does_not_settle_stops_before_anything_is_filled(monkeypatch):
    monkeypatch.setattr(w, "settled_fields", lambda page, type_text: ([], False))
    page = add_page()
    with pytest.raises(w.WriteStepError) as caught:
        add_step(page, plan("add", type_="A", host="www", content="1.2.3.4"))
    assert caught.value.step == "add_type"
    assert not [e for e in page.events if e[0] in ("fill", "check")]


def test_select_falls_back_to_the_option_text_when_no_value_matches():
    page = FakePage(counts={f'{ADD_FORM} select[name=tag] option[value="issue"]': 0},
                    lists={f"{ADD_FORM} select[name=tag] option": ["issue - Allow", "iodef"]})
    w._select_option(page, f"{ADD_FORM} select[name=tag]", "issue", "caa_tag")
    assert ("select", f"{ADD_FORM} select[name=tag]", "issue - Allow") in page.events


def test_tool_add_passes_fields_and_reports_the_values(monkeypatch):
    reads(monkeypatch, pages_of(BASE))
    result = t.record_add("TXT", "www", fields={"content": "v=spf1 -all"}, runner=runner_for(add_page()))
    assert result["ok"] is True and result["values"] == {"content": "v=spf1 -all"}


def test_tool_reads_the_schema_for_a_zone_wide_type_and_previews_it(monkeypatch):
    reads(monkeypatch, pages_of(BASE))
    asked = []

    def offered(page, record_type):
        asked.append(record_type)
        return zone_wide_schema(record_type)

    monkeypatch.setattr(w, "schema_open", offered)
    page = add_page()
    result = t.record_add("NS", "www", "ns.example.net.", runner=runner_for(page))
    assert asked == ["NS"] and result["ok"] is True and result["confirmed"] is False
    assert not [e for e in page.events if e[0] in ("fill", "check", "click")]


def test_tool_refuses_unknown_types_before_any_schema_read(monkeypatch):
    reads(monkeypatch, pages_of(BASE), pages_of(BASE))
    page = add_page()
    assert t.record_add("SRV", "www", "x", runner=runner_for(page)) == {
        "ok": False, "action": "add", "refused": "bad_type", "domain": DOMAIN}
    assert page.events == []


def test_tool_refuses_when_the_schema_does_not_settle(monkeypatch):
    reads(monkeypatch, pages_of(BASE))

    def unsettled(page, record_type):
        raise s.SchemaUnavailable()

    monkeypatch.setattr(w, "schema_open", unsettled)
    page = add_page()
    result = t.record_add("A", "www", "1.2.3.4", confirmed=True, runner=runner_for(page))
    assert result == {"ok": False, "action": "add", "refused": "schema_unavailable", "domain": DOMAIN}
    assert page.events == []


def test_tool_delete_by_hash_previews_without_a_content_argument(monkeypatch):
    reads(monkeypatch, pages_of(BASE))
    page = FakePage()
    result = t.record_delete("CNAME", "home", expect_hash=HOME_HASH, runner=runner_for(page))
    assert result["ok"] is True and result["before"] and result["after"] is None
    assert page.events == []


def test_server_write_tools_take_fields_and_hash_with_empty_defaults():
    tools = {tool.name: tool for tool in asyncio.run(srv.mcp.list_tools())}
    add_props = tools["zoneedit_record_add"].inputSchema["properties"]
    update_props = tools["zoneedit_record_update"].inputSchema["properties"]
    delete_props = tools["zoneedit_record_delete"].inputSchema["properties"]
    assert "fields" in add_props and "fields" in update_props
    assert "expect_hash" in update_props and "expect_hash" in delete_props
    assert "content" not in tools["zoneedit_record_add"].inputSchema.get("required", [])
    assert "expect_content" not in tools["zoneedit_record_delete"].inputSchema.get("required", [])


def test_select_chooses_by_value_attribute_before_option_text():
    page = FakePage(lists={f"{ADD_FORM} select[name=tag] option": ["Label A"]})
    w._select_option(page, f"{ADD_FORM} select[name=tag]", "x1", "caa_tag")
    assert ("select", f"{ADD_FORM} select[name=tag]", "x1") in page.events


# --- Rework round 1: DMARC and URL plans, PARK, options_total, and the pinned choices ----------

DMARC_POLICIES = ["none", "quarantine", "reject"]
DMARC_SCHEMA = {"type_names": ["DMARC"], "ttl_options": TTL_LABELS, "fields": [
    _field("host", "Selector", "text"),
    _field("policy", "Policy", "select", options=DMARC_POLICIES),
    _field("sp", "Subdomain policy", "select", options=DMARC_POLICIES),
    _TTL]}
URL_SCHEMA = {"type_names": ["URL"], "ttl_options": TTL_LABELS, "fields": [
    _field("host", "Host", "text"),
    _field("content", "Target URL", "text", required=True),
    _field("https", "Force HTTPS", "checkbox"),
    _field("perm", "Permanent", "checkbox"),
    _field("dropath", "Drop path", "checkbox"),
    _field("dropquery", "Drop query", "checkbox"),
    _field("cc", "Cache", "select", options=["301 - Permanent", "302 - Temporary"], required=True)]}
PARK_SCHEMA = {"type_names": ["PARK"], "ttl_options": TTL_LABELS, "fields": [_field("host", "Host", "text"), _TTL]}


def dmarc(**kw):
    return w.plan_write("add", [], type_="DMARC", host="_dmarc", domain=DOMAIN, schema=DMARC_SCHEMA, **kw)


def url(**kw):
    return w.plan_write("add", [], type_="URL", host="go", domain=DOMAIN, schema=URL_SCHEMA, **kw)


def test_dmarc_good_plan_takes_its_optional_selects_and_ttl():
    result = dmarc(fields={"policy": "reject", "sp": "none"}, ttl="1 hour")
    assert "refused" not in result
    assert result["values"] == {"policy": "reject", "sp": "none"} and result["ttl"] == "1 hour"


def test_dmarc_refuses_a_select_value_outside_a_complete_list():
    assert dmarc(fields={"policy": "maybe"}) == {"refused": "bad_option"}


def test_dmarc_refuses_an_unknown_field():
    assert dmarc(fields={"nosuch": "x"}) == {"refused": "unknown_field"}


def test_dmarc_add_with_no_fields_plans_because_no_field_is_required():
    result = dmarc()
    assert "refused" not in result and result["values"] == {}


def test_url_good_plan_takes_its_checkboxes_select_and_content():
    result = url(content="https://example.net/x", fields={"https": "yes", "perm": "no", "cc": "302"})
    assert "refused" not in result
    assert result["values"] == {"content": "https://example.net/x", "https": "yes", "perm": "no", "cc": "302"}


def test_url_refuses_a_select_value_outside_a_complete_list():
    assert url(content="https://example.net/x", fields={"cc": "999"}) == {"refused": "bad_option"}


def test_url_refuses_a_checkbox_value_outside_the_boolean_set():
    assert url(content="https://example.net/x", fields={"https": "sometimes", "cc": "302"}) == {
        "refused": "bad_option"}


def test_url_refuses_an_unknown_field():
    assert url(content="https://example.net/x", fields={"nosuch": "x", "cc": "302"}) == {
        "refused": "unknown_field"}


def test_url_refuses_a_missing_required_select_by_name():
    assert url(content="https://example.net/x") == {"refused": "missing_field", "missing": ["cc"]}


def test_park_add_with_only_a_host_and_a_ttl_plans():
    result = w.plan_write("add", [], type_="PARK", host="park", domain=DOMAIN, schema=PARK_SCHEMA, ttl="1 hour")
    assert "refused" not in result and result["values"] == {} and result["ttl"] == "1 hour"


def test_an_a_add_with_no_content_is_still_empty_content():
    assert plan("add", type_="A", host="www") == {"refused": "empty_content"}


def test_an_mx_add_with_no_prio_is_still_bad_prio():
    assert plan("add", type_="MX", host="mx", content="mail.example.com") == {"refused": "bad_prio"}


def test_a_truncated_select_accepts_an_unlisted_value_at_plan_time_and_the_page_step_raises():
    truncated = dict(_field("policy", "Policy", "select", options=["p0", "p1"]), options_total=100)
    schema = {"type_names": ["POL"], "ttl_options": TTL_LABELS, "fields": [truncated]}
    planned = w.plan_write("add", [], type_="POL", host="pol", domain=DOMAIN, schema=schema,
                           fields={"policy": "p99"})
    assert "refused" not in planned and planned["values"] == {"policy": "p99"}
    page = FakePage(counts={f'{ADD_FORM} select[name=policy] option[value="p99"]': 0},
                    lists={f"{ADD_FORM} select[name=policy] option": ["p0", "p1"]})
    with pytest.raises(w.WriteStepError) as caught:
        w._select_option(page, f"{ADD_FORM} select[name=policy]", "p99", "policy")
    assert caught.value.step == "policy"
    assert not [e for e in page.events if e[0] == "select"]


def test_a_complete_select_still_refuses_a_wrong_value():
    complete = dict(_field("policy", "Policy", "select", options=["p0", "p1"]), options_total=2)
    schema = {"type_names": ["POL"], "ttl_options": TTL_LABELS, "fields": [complete]}
    assert w.plan_write("add", [], type_="POL", host="pol", domain=DOMAIN, schema=schema,
                        fields={"policy": "p99"}) == {"refused": "bad_option"}


def test_empty_string_field_values_are_dropped_and_a_required_one_then_reads_as_missing():
    assert srv_plan(content="t", fields={"service": ""}) == {"refused": "missing_field", "missing": ["service"]}
    assert "proto" not in srv_plan(content="t", fields={"service": "_sip", "proto": ""})["values"]


def test_the_trailing_dot_for_cname_and_mx_applies_to_the_fields_content_too():
    cname = plan("add", type_="CNAME", host="newname", fields={"content": "host.example.com"})
    assert cname["values"]["content"] == "host.example.com." and cname["content"] == "host.example.com."
    mx = plan("add", type_="MX", host="mx", fields={"content": "mail.example.com", "prio": "10"})
    assert mx["values"]["content"] == "mail.example.com."


def test_a_hash_only_delete_reads_back_its_lines_with_an_empty_needle(monkeypatch):
    planned = plan("delete", ROWS, type_="CNAME", host="home", expect_hash=HOME_HASH)
    assert planned["expect"] == "target.example.net." and planned["content"] == ""
    fake_dig(monkeypatch, stdout="target.example.net.\n")
    readback, matches = w.dns_readback("delete", "CNAME", "home", "", DOMAIN, ["ns1.example.net"])
    assert readback == {"ns1.example.net": {"lines": ["target.example.net."]}}
    assert matches == {}


# --- Rework round 2: disabled required fields and the optional host ----------------------------

def test_caa_fields_only_add_without_the_disabled_flag_plans():
    planned = plan("add", type_="CAA", host="www", fields={"tag": "issue", "provider": "letsencrypt.org"})
    assert "refused" not in planned and "flag" not in planned["values"]


def test_caa_fields_only_add_leaves_the_disabled_flag_unfilled_on_the_page(monkeypatch):
    page = add_page(disabled=(ADD_FLAG,))
    add_step(page, plan("add", type_="CAA", host="www", fields={"tag": "issue", "provider": "letsencrypt.org"}))
    assert not [e for e in page.events if e[0] == "fill" and e[1] == ADD_FLAG]
    assert ("select", f"{ADD_FORM} select[name=provider]", "letsencrypt.org") in page.events


def test_caa_with_nothing_is_missing_exactly_tag_and_provider():
    assert plan("add", type_="CAA", host="www") == {"refused": "missing_field", "missing": ["tag", "provider"]}


def test_a_legacy_caa_add_still_plans_and_carries_the_flag_default_through_the_placeholder_rule():
    planned = plan("add", type_="CAA", host="www", content="0 issue letsencrypt.org")
    assert "refused" not in planned and planned["values"]["flag"] == "0"


def test_an_optional_host_of_empty_or_at_plans_the_apex_and_does_not_fill_the_host():
    for host in ("", "@"):
        planned = w.plan_write("add", [], type_="DMARC", host=host, domain=DOMAIN, schema=DMARC_SCHEMA,
                               fields={"policy": "none"})
        assert "refused" not in planned
        assert planned["host"] == "@" and planned["fill_host"] is False


def test_an_optional_host_with_a_name_is_filled():
    planned = w.plan_write("add", [], type_="DMARC", host="sel1", domain=DOMAIN, schema=DMARC_SCHEMA,
                           fields={"policy": "none"})
    assert planned["host"] == "sel1" and planned["fill_host"] is True


def test_an_optional_empty_host_still_meets_cname_conflict_at_the_apex():
    dmarc_rows = [_dict("DMARC", "@", "v=DMARC1", "hd")]
    further = w.plan_write("add", dmarc_rows, type_="DMARC", host="", domain=DOMAIN, schema=DMARC_SCHEMA,
                           fields={"policy": "none"})
    assert "refused" not in further and len(further["before"]) == 1
    cname_rows = [_dict("CNAME", "@", "x.example.net.", "hc")]
    assert w.plan_write("add", cname_rows, type_="DMARC", host="", domain=DOMAIN, schema=DMARC_SCHEMA,
                        fields={"policy": "none"}) == {"refused": "cname_conflict"}


def test_a_required_host_still_refuses_an_empty_host():
    assert plan("add", type_="A", host="", content="1.2.3.4") == {"refused": "bad_host"}
    assert plan("add", type_="TXT", host="", fields={"content": "v=x"}) == {"refused": "bad_host"}


# --- Round 3: the plan matches rows with the schema's spelling of the type -----------------------

def mixed_schema(spelling, fields):
    """A schema whose type is spelled ``spelling`` (not all capitals), for the spelling invariant."""
    return {"type_names": [spelling], "ttl_options": TTL_LABELS, "fields": fields}


def test_a_lowercase_txt_add_on_a_host_with_a_txt_row_lists_that_row_as_before():
    rows = [_dict("TXT", "www", "v=x", "ht")]
    planned = plan("add", rows, type_="txt", host="www", content="v=y")
    assert "refused" not in planned and [r["hash"] for r in planned["before"]] == ["ht"]


def test_a_lowercase_cname_add_on_a_host_with_other_rows_is_refused_cname_conflict():
    rows = [_dict("A", "home", "1.2.3.4", "ha")]
    assert plan("add", rows, type_="cname", host="home", content="x.example.") == {"refused": "cname_conflict"}


def test_a_lowercase_update_and_delete_find_the_row_and_a_wrong_type_is_not_found():
    upd = plan("update", ROWS, type_="cname", host="home", expect="target.example.net.", content="new.example.")
    assert upd["target"]["hash"] == HOME_HASH
    dele = plan("delete", ROWS, type_="cname", host="meet", expect="target.example.net.")
    assert dele["target"]["hash"] == MEET_HASH
    assert plan("delete", ROWS, type_="a", host="home", expect="target.example.net.") == {"refused": "not_found"}
    assert plan("update", ROWS, type_="a", host="home", expect="target.example.net.",
                content="x.example.") == {"refused": "not_found"}


def test_the_plan_type_carries_the_schema_spelling_for_a_lowercase_request():
    planned = w.plan_write("add", [], type_="txt", host="www", domain=DOMAIN,
                           schema=mixed_schema("Txt", TABLE["TXT"]), content="v=y")
    assert planned["type"] == "Txt"
    assert plan("add", [], type_="txt", host="www", content="v=y")["type"] == "TXT"


def test_rows_are_matched_with_the_schema_spelling_so_a_lowercase_add_still_lists_the_old_row():
    rows = [_dict("Txt", "www", "v=x", "ht")]
    planned = w.plan_write("add", rows, type_="txt", host="www", domain=DOMAIN,
                           schema=mixed_schema("Txt", TABLE["TXT"]), content="v=y")
    assert "refused" not in planned and [r["hash"] for r in planned["before"]] == ["ht"]


def test_verify_add_fails_when_the_panel_replaced_a_row_instead_of_adding():
    add = plan("add", BASE_ROWS, type_="A", host="www", content="1.2.3.4")
    pages = pages_of([r for r in BASE if ">mail<" not in r] + [_row("A", "www", "1.2.3.4", "h9")])
    assert any("another row vanished" in d for d in w.verify(add, pages))
