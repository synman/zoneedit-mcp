"""Click paths for add, update and delete, driven through the shipped steps in ``zoneedit_writes``
against the SYNTHETIC test pages in ``tests/fixtures``, in a real headless Chromium with the network off.

The pages are written for these tests with invented data and carry no panel JavaScript. They were
checked against a real panel snapshot: every selector the steps use matched the same number of
elements on both, before and after a form was revealed. That snapshot is in git history only. Where a
step needs a click to open a form, one small inline script from ``tests/fixtures/*.html`` is inserted
before ``</body>``: a minimal model, not a recording. Every request is aborted except the DNS page,
which is answered from the synthetic HTML. Variants of that HTML (checked switch, duplicated row,
hidden nav) are made in memory.

Patchright runs ``page.evaluate`` in an isolated JavaScript world, so the scripts log into a DOM
attribute (``data-model-log``), which both worlds share, and the tests read it back with ``log``.
"""
import inspect
import json
from pathlib import Path

import pytest
from real_browser import chrome, make_page  # noqa: F401  (pytest fixtures, shared with test_schema_dom)

import zoneedit_session as s
import zoneedit_writes as w
from zoneedit_panel import parse_records

FIX = Path(__file__).parent / "fixtures"
DOMAIN = "example.com"
DNS_PATH = s.dns_url_for(DOMAIN).split("?", 1)[0]
HOME = "0561cdb77715b0b0a4ec5e0df3c7cfa7"


CLICK_TTL = ["[DEF] 2 hours", "5 minutes", "1 hour", "1 day"]
CLICK_TABLE = {
    "A": [{"name": "host", "label": "Host", "kind": "text", "required": True, "disabled": False},
          {"name": "content", "label": "IP address", "kind": "text", "required": True, "disabled": False},
          {"name": "ttl", "label": "TTL", "kind": "select", "required": False, "disabled": False,
           "options": CLICK_TTL}],
    "CNAME": [{"name": "host", "label": "Host", "kind": "text", "required": True, "disabled": False},
              {"name": "content", "label": "Target", "kind": "text", "required": True, "disabled": False},
              {"name": "ttl", "label": "TTL", "kind": "select", "required": False, "disabled": False,
               "options": CLICK_TTL}],
}


def plan_write(action, rows, **kwargs):
    """The shipped planner for the click-path domain: every plan here is for DOMAIN. Add and update get
    the schema of their type, as ``schema_open`` would read it from the live form."""
    schema = None if action == "delete" else {"type_names": list(CLICK_TABLE),
                                              "fields": CLICK_TABLE.get(kwargs["type_"].upper(), []),
                                              "ttl_options": CLICK_TTL}
    return w.plan_write(action, rows, domain=DOMAIN, schema=schema, **kwargs)

MEET = "6c563b24326786e448d2196f11d58326"
BAD_HASH = "0" * 32
ADD_FORM = "form[name=formAddRecord]:visible"
EDIT_FORM_OF_HOME = "form#form-edit-record-" + HOME
CLICK_RECORDER = ("<script>document.addEventListener('click', function (e) {"
                  "var t = e.target.closest('button,a'); if (!t) { return; }"
                  "var root = document.documentElement;"
                  "var log = JSON.parse(root.getAttribute('data-model-log') || '{}');"
                  "(log.clicks = log.clicks || []).push(t.id || t.getAttribute('aria-label') || '');"
                  "root.setAttribute('data-model-log', JSON.stringify(log));"
                  "}, true);</script>")


def _fixture(name):
    return (FIX / name).read_text(encoding="utf-8")


SAVED_DNS = _fixture("dns_index.html")
SAVED_ADD = _fixture("add_form.html")
BOOT = _fixture("bootstrap_display_model.html")
ADD_SCRIPT = _fixture("add_reveal_script.html")
EDIT_SCRIPT = _fixture("edit_reveal_script.html")
PAGE_SCRIPT = _fixture("pagination_click_recorder.html")
ROWS = parse_records(SAVED_DNS)


def page_of(base, *parts):
    """Insert parts before </body>, or append when the fixture is a bare fragment."""
    end = base.rfind("</body>")
    if end == -1:
        return base + "".join(parts)
    return base[:end] + "".join(parts) + base[end:]


def dns_page(*parts, base=SAVED_DNS):
    return page_of(base, BOOT, *parts)


def block_of(html, marker):
    """The one <form ...> block containing ``marker`` (the marker sits inside its opening tag)."""
    at = html.index(marker)
    start = html.rindex("<form", 0, at)
    end = html.index("</form>", at) + len("</form>")
    return html[start:end]


def change_block(html, marker, change):
    block = block_of(html, marker)
    return html.replace(block, change(block), 1)


def run_script(js):
    return f"<script>document.addEventListener('DOMContentLoaded', function () {{ {js} }});</script>"


def log(page, key):
    """The model's log entries for ``key`` (a list), or None when nothing was logged."""
    return page.evaluate(
        f"(JSON.parse(document.documentElement.getAttribute('data-model-log') || '{{}}'))[{json.dumps(key)}] || null")


@pytest.fixture(autouse=True)
def short_waits(monkeypatch):
    # The shipped steps pause 1.5 s after each click for the live panel. The model reacts at once.
    monkeypatch.setattr(w, "ACTION_WAIT_MS", 50)


def serve(page, html):
    """Answer the DNS page from ``html``. Registered after the abort-all route, so it wins."""
    def handle(route):
        route.fulfill(status=200, content_type="text/html; charset=utf-8", body=html)

    page.context.route(lambda url: url.split("?", 1)[0] == DNS_PATH, handle)


def source_has(fn, *fragments):
    src = inspect.getsource(fn)
    for fragment in fragments:
        assert fragment in src, f"{fragment!r} is no longer in {fn.__name__}"


# --- Saved markup: each locator matches once; the edit form is hidden until its EDIT click ----

def test_saved_add_form_locators_match_once_and_save_is_save(make_page):
    page = make_page()
    page.set_content(page_of(SAVED_ADD, BOOT))
    form = ADD_FORM
    for sel in [form, f"{form} select[name=type]", f"{form} input[name=host]",
                f"{form} input[name=content]", f"{form} select[name=ttl]",
                f"{form} button[type=submit].btn-success:visible"]:
        assert page.locator(sel).count() == 1, sel
    save = page.locator(f"{form} button[type=submit].btn-success:visible").inner_text()
    assert save.strip().endswith("Save")
    for sel in [f"{form} button.btn-warning:visible", f"{form} [data-field^='warn_']:visible"]:
        assert page.locator(sel).count() == 0, sel
    source_has(w._add, "form[name=formAddRecord]:visible", "select[name=type]",
               "input[name=host]", "button[type=submit].btn-success:visible")
    source_has(w._field_selector, "input", "[name=")
    source_has(w._select_ttl, "select[name=ttl]")
    source_has(w._refuse_on_confirm, "button.btn-warning:visible", "[data-field^='warn_']:visible")


def test_saved_add_form_ttl_option_selected_and_absent_option_aborts(make_page):
    page = make_page()
    page.set_content(page_of(SAVED_ADD, BOOT))
    w._select_ttl(page, ADD_FORM, "1 hour")
    assert page.locator(f"{ADD_FORM} select[name=ttl]").input_value() == "3600"
    with pytest.raises(w.WriteStepError) as caught:
        w._select_ttl(page, ADD_FORM, "7 hours")
    assert caught.value.step == "ttl_option"


def test_saved_dns_add_button_scan_clicks_the_add_record_button(make_page):
    page = make_page()
    page.set_content(dns_page(CLICK_RECORDER))
    w._click_add_button(page)
    assert log(page, "clicks") == ["addBtn"]


def test_add_button_step_aborts_when_no_add_control_matches(make_page):
    page = make_page()
    page.set_content(page_of(SAVED_ADD, BOOT))
    with pytest.raises(w.WriteStepError) as caught:
        w._click_add_button(page)
    assert caught.value.step == "add_button"


@pytest.mark.xfail(strict=True, reason=(
    "defect: _click_add_button takes the LAST visible ADD control and never aborts on two matches; "
    "the brief's count-2 rule is not met by this step"))
def test_add_button_step_aborts_when_two_add_controls_match(make_page):
    second = '<button type="button" class="btn btn-primary" id="addBtnTwo">Add</button>'
    page = make_page()
    page.set_content(dns_page(second))
    with pytest.raises(w.WriteStepError) as caught:
        w._click_add_button(page)
    assert caught.value.step == "add_button"


# --- Add click path ---------------------------------------------------------------------------

def test_add_click_reveals_the_form_and_only_the_add_button_is_clicked(make_page):
    page = make_page()
    serve(page, dns_page(ADD_SCRIPT, CLICK_RECORDER))
    w._goto_dns(page, DOMAIN)
    w._click_add_button(page)
    assert log(page, "addClicked") == ["addBtn"]
    assert log(page, "clicks") == ["addBtn"]
    assert page.locator(ADD_FORM).count() == 1


def test_add_full_path_fills_and_saves_the_revealed_form(make_page):
    page = make_page()
    serve(page, dns_page(ADD_SCRIPT))
    plan = plan_write("add", ROWS, type_="A", host="www", content="192.0.2.7")
    assert "refused" not in plan
    w._add(page, plan, DOMAIN)
    assert log(page, "saved") == ["addForm"]
    assert page.locator(f"{ADD_FORM} input[name=host]").input_value() == "www"
    assert page.locator(f"{ADD_FORM} input[name=content]").input_value() == "192.0.2.7"
    assert page.locator(f"{ADD_FORM} select[name=type]").input_value() == "A"


@pytest.mark.parametrize("shown", ["warn", "confirm"])
def test_replace_prompt_shown_before_save_refuses_and_never_clicks_confirm(make_page, shown):
    if shown == "warn":
        base = change_block(SAVED_DNS, 'name="formAddRecord"',
                            lambda b: b.replace('data-field="warn_h" style="display: none;"',
                                                'data-field="warn_h"'))
    else:
        base = change_block(SAVED_DNS, 'name="formAddRecord"',
                            lambda b: b.replace('class="btn btn-warning ms-2" style="display: none;"',
                                                'class="btn btn-warning ms-2"'))
    page = make_page()
    serve(page, dns_page(ADD_SCRIPT, base=base))
    plan = plan_write("add", ROWS, type_="A", host="www", content="192.0.2.7")
    with pytest.raises(w.PanelRefusal) as caught:
        w._add(page, plan, DOMAIN)
    assert caught.value.reason == "replace_prompt_shown"
    assert log(page, "saved") is None
    assert log(page, "confirmFired") is None


def test_replace_prompt_shown_after_save_stops_without_clicking_confirm(make_page):
    after_save = ("<script>document.addEventListener('click', function (e) {"
                  "if (e.target.closest('form[name=formAddRecord] button[type=submit]')) {"
                  "document.querySelectorAll('form[name=formAddRecord] [data-field=warn_h], "
                  "form[name=formAddRecord] button.btn-warning').forEach(function (x) {"
                  "x.style.display = 'block'; }); } }, false);</script>")
    page = make_page()
    serve(page, dns_page(ADD_SCRIPT, after_save))
    plan = plan_write("add", ROWS, type_="A", host="www", content="192.0.2.7")
    with pytest.raises(w.PanelRefusal):
        w._add(page, plan, DOMAIN)
    assert log(page, "saved") == ["addForm"]
    assert log(page, "confirmFired") is None


def test_add_step_aborts_at_add_type_when_no_form_opens(make_page):
    page = make_page()
    serve(page, dns_page())
    plan = plan_write("add", ROWS, type_="A", host="www", content="192.0.2.7")
    with pytest.raises(w.WriteStepError) as caught:
        w._add(page, plan, DOMAIN)
    assert caught.value.step == "add_type"


def test_add_step_aborts_at_add_type_when_two_forms_match(make_page):
    doubled = change_block(SAVED_DNS, 'name="formAddRecord"', lambda b: b + b)
    page = make_page()
    serve(page, dns_page(ADD_SCRIPT, base=doubled))
    plan = plan_write("add", ROWS, type_="A", host="www", content="192.0.2.7")
    with pytest.raises(w.WriteStepError) as caught:
        w._add(page, plan, DOMAIN)
    assert caught.value.step == "add_type"
    assert log(page, "saved") is None


# --- Edit (update and delete) click path ------------------------------------------------------

def test_saved_edit_form_is_hidden_until_edit_is_clicked(make_page):
    page = make_page()
    page.set_content(dns_page())
    row = f"div.item-wrapped[data-hash='{HOME}']"
    assert page.locator(row).count() == 1
    assert page.locator(f"{row} button.btn-edit:visible").count() == 1
    assert page.locator(f"{row} form[name=formEditRecord]").count() == 1
    assert page.locator(f"{row} form[name=formEditRecord]:visible").count() == 0
    page.evaluate(f"document.getElementById('form-edit-record-{HOME}').style.display = 'block'")
    edit = f"{row} form[name=formEditRecord]:visible"
    assert page.locator(f"{edit} input[name=content]").count() == 1
    assert page.locator(f"{edit} button.btn-success:visible").count() == 1
    assert page.locator(f"{edit} button.btn-warning:visible").count() == 0
    assert page.locator(f"{edit} [data-field^='warn_']:visible").count() == 0
    assert page.locator(f"{edit} button.btn-danger:visible:has-text('Delete')").count() == 1
    source_has(w._row_scope, "div.item-wrapped[data-hash='")
    source_has(w._change, "button.btn-edit:visible", "form[name=formEditRecord]:visible",
               "button.btn-danger:visible:has-text('Delete')", "button.btn-success:visible")


def test_update_clicks_the_home_row_edit_then_saves_only_that_row(make_page):
    page = make_page()
    serve(page, dns_page(EDIT_SCRIPT))
    plan = plan_write("update", ROWS, type_="CNAME", host="home",
                        expect="target.example.net.", content="new.example.")
    assert plan["target"]["hash"] == HOME
    w._change(page, plan, DOMAIN)
    assert log(page, "editClicked") == [HOME]
    assert log(page, "saved") == [HOME]
    assert log(page, "deleted") is None
    assert page.locator(f"{EDIT_FORM_OF_HOME} input[name=content]").input_value() == "new.example."


def test_delete_clicks_the_meet_row_edit_then_its_delete_only(make_page):
    page = make_page()
    serve(page, dns_page(EDIT_SCRIPT))
    plan = plan_write("delete", ROWS, type_="CNAME", host="meet",
                        expect="target.example.net.")
    assert plan["target"]["hash"] == MEET
    w._change(page, plan, DOMAIN)
    assert log(page, "editClicked") == [MEET]
    assert log(page, "deleted") == [MEET]
    assert log(page, "saved") is None


def test_row_step_aborts_on_zero_matches(make_page):
    page = make_page()
    serve(page, dns_page(EDIT_SCRIPT))
    plan = plan_write("update", ROWS, type_="CNAME", host="home",
                        expect="target.example.net.", content="new.example.")
    plan["target"] = dict(plan["target"], hash=BAD_HASH)
    with pytest.raises(w.WriteStepError) as caught:
        w._change(page, plan, DOMAIN)
    assert caught.value.step == "row"


def test_row_step_aborts_on_two_matches(make_page):
    doubled = dns_page(EDIT_SCRIPT, run_script(
        f"var row = document.querySelector(\"div.item-wrapped[data-hash='{HOME}']\");"
        "row.parentNode.appendChild(row.cloneNode(true));"))
    page = make_page()
    serve(page, doubled)
    plan = plan_write("update", ROWS, type_="CNAME", host="home",
                        expect="target.example.net.", content="new.example.")
    with pytest.raises(w.WriteStepError) as caught:
        w._change(page, plan, DOMAIN)
    assert caught.value.step == "row"
    assert log(page, "editClicked") is None


def test_edit_button_step_aborts_on_zero_matches(make_page):
    base = SAVED_DNS.replace("btn-edit btn-primary", "btn-primary")
    page = make_page()
    serve(page, dns_page(EDIT_SCRIPT, base=base))
    plan = plan_write("update", ROWS, type_="CNAME", host="home",
                        expect="target.example.net.", content="new.example.")
    with pytest.raises(w.WriteStepError) as caught:
        w._change(page, plan, DOMAIN)
    assert caught.value.step == "edit_button"


def test_edit_button_step_aborts_on_two_matches(make_page):
    doubled = dns_page(EDIT_SCRIPT, run_script(
        f"var row = document.querySelector(\"div.item-wrapped[data-hash='{HOME}']\");"
        "row.appendChild(row.querySelector('button.btn-edit').cloneNode(true));"))
    page = make_page()
    serve(page, doubled)
    plan = plan_write("update", ROWS, type_="CNAME", host="home",
                        expect="target.example.net.", content="new.example.")
    with pytest.raises(w.WriteStepError) as caught:
        w._change(page, plan, DOMAIN)
    assert caught.value.step == "edit_button"
    assert log(page, "editClicked") is None


def test_delete_button_step_aborts_on_zero_matches_after_the_edit_click(make_page):
    base = SAVED_DNS.replace('class="btn btn-danger"><i class="bi bi-trash3-fill"></i> Delete</button>',
                             'class="btn btn-dangerX"><i class="bi bi-trash3-fill"></i> Delete</button>')
    page = make_page()
    serve(page, dns_page(EDIT_SCRIPT, base=base))
    plan = plan_write("delete", ROWS, type_="CNAME", host="meet", expect="target.example.net.")
    with pytest.raises(w.WriteStepError) as caught:
        w._change(page, plan, DOMAIN)
    assert caught.value.step == "delete_button"
    assert log(page, "editClicked") == [MEET]
    assert log(page, "deleted") is None


def test_delete_button_step_aborts_on_two_matches_without_the_delete_click(make_page):
    doubled = dns_page(EDIT_SCRIPT, run_script(
        f"var form = document.getElementById('form-edit-record-{MEET}');"
        "form.appendChild(form.querySelector('button.btn-danger').cloneNode(true));"))
    page = make_page()
    serve(page, doubled)
    plan = plan_write("delete", ROWS, type_="CNAME", host="meet", expect="target.example.net.")
    with pytest.raises(w.WriteStepError) as caught:
        w._change(page, plan, DOMAIN)
    assert caught.value.step == "delete_button"
    assert log(page, "deleted") is None


# --- Pagination -------------------------------------------------------------------------------

def test_pagination_click_uses_the_first_nav_when_both_are_visible(make_page):
    page = make_page()
    serve(page, dns_page(PAGE_SCRIPT))
    w._goto_dns(page, DOMAIN, 2)
    assert log(page, "pageNav") == [0]


def test_pagination_click_uses_the_first_visible_nav(make_page):
    hidden_first = SAVED_DNS.replace('<nav aria-label="DNS pagination"',
                                     '<nav style="display: none" aria-label="DNS pagination"', 1)
    page = make_page()
    serve(page, dns_page(PAGE_SCRIPT, base=hidden_first))
    w._goto_dns(page, DOMAIN, 2)
    assert log(page, "pageNav") == [1]


def test_pagination_step_aborts_when_no_nav_exists(make_page):
    page = make_page()
    serve(page, SAVED_ADD)
    with pytest.raises(w.WriteStepError) as caught:
        w._goto_dns(page, DOMAIN, 2)
    assert caught.value.step == "pagination"


# --- read_bulk_save_off on the live switch ----------------------------------------------------

SWITCH = 'role="switch" id="editor_bulk_save_mode" value="false">'


@pytest.mark.parametrize("html, expected", [
    (SAVED_DNS, True),
    (SAVED_DNS.replace(SWITCH, 'role="switch" id="editor_bulk_save_mode" value="true">'), True),
    (SAVED_DNS.replace(SWITCH, SWITCH[:-1] + " checked>"), False),
    (SAVED_DNS.replace(SWITCH, 'role="switch" id="editor_bulk_save_mode" value="true" checked>'), False),
    (SAVED_DNS.replace('id="editor_bulk_save_mode" value="false">',
                       'id="editor_bulk_save_modeX" value="false">'), None),
    (SAVED_DNS.replace(SWITCH, SWITCH + '<input type="checkbox" id="editor_bulk_save_mode">'), None),
], ids=["unchecked", "unchecked-static-value-true", "checked", "checked-static-value-true",
        "absent", "duplicated"])
def test_read_bulk_save_off_reads_the_live_switch(make_page, html, expected):
    page = make_page()
    page.set_content(page_of(html, BOOT))
    assert s.read_bulk_save_off(page) is expected
