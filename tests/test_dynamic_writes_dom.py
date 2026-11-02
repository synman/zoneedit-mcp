"""Schema-driven add and update driven through a real offline Chrome, against ``tests/fixtures/write_model.html``.

The model logs every click, every saved add field (name and value), every saved edit field and every type
change into its DOM attribute. Each test reads the schema from the live model with ``schema_open``, plans the
write with the shipped planner, and runs the shipped page step. The CAA flag is disabled on both forms with
placeholder "0", as on the live panel. Settle and wait times are scaled down.
"""
import json
from pathlib import Path

import pytest
from real_browser import chrome, make_page  # noqa: F401  (pytest fixtures)

import zoneedit_session as s
import zoneedit_writes as w

MODEL = (Path(__file__).parent / "fixtures" / "write_model.html").read_text(encoding="utf-8")
PANEL_PREFIX = "https://cp.zoneedit.com/manage/domains/"
DOMAIN = "example.com"
ROW_HASH = "a1b2c3"
DEFAULT_TTL = "[DEF] 2 hours"


@pytest.fixture(autouse=True)
def quick_waits(monkeypatch):
    monkeypatch.setattr(s, "SETTLE_MS", 400)
    monkeypatch.setattr(w, "LOAD_WAIT_MS", 50)
    monkeypatch.setattr(w, "ACTION_WAIT_MS", 50)


@pytest.fixture
def editor(make_page):
    """A page whose panel requests are answered by the write model, served fresh on every navigation."""
    page = make_page()

    def handle(route):
        route.fulfill(status=200, content_type="text/html; charset=utf-8", body=MODEL)

    page.context.route(lambda url: url.startswith(PANEL_PREFIX), handle)
    return page


def log(page, key):
    """The model's log entries for ``key`` (a list), or None when nothing was logged."""
    return page.evaluate(
        f"(JSON.parse(document.documentElement.getAttribute('data-model-log') || '{{}}'))[{json.dumps(key)}] || null")


def schema_of(page, type_):
    """The type's schema as ``schema_open`` reads it from the live add form. The read clicks the add button,
    so the caller's write navigates again before it clicks anything."""
    page.goto(s.dns_url_for(DOMAIN), wait_until="domcontentloaded")
    return s.schema_open(page, type_)


def plan_for(page, action, type_, rows=(), **kw):
    schema = schema_of(page, type_)
    return w.plan_write(action, list(rows), type_=type_, host=kw.pop("host"), domain=DOMAIN, schema=schema, **kw)


def caa_rows():
    return [{"type": "CAA", "host": "@", "content": "0 issue letsencrypt.org", "ttl": "", "prio": "",
             "hash": ROW_HASH}]


# --- Add: fields are filled from the schema and exactly those are saved ----------------------------

def test_add_mx_fills_host_content_prio_and_ttl_then_saves_exactly_those(editor):
    plan = plan_for(editor, "add", "MX", host="mail", content="mx.example.net", prio="10", ttl="1 hour")
    w._add(editor, plan, DOMAIN)
    assert log(editor, "saved") == [{"host": "mail", "content": "mx.example.net.", "prio": "10",
                                     "ttl": "1 hour"}]
    assert log(editor, "clicks") == ["addBtn", "saveAdd"]


def test_add_srv_chooses_the_proto_option_by_its_part_before_the_dash(editor):
    plan = plan_for(editor, "add", "SRV", host="_sip", content="sip.example.net",
                    fields={"service": "_sip", "proto": "_tcp", "prio": "0", "weight": "5", "port": "5060"})
    w._add(editor, plan, DOMAIN)
    assert log(editor, "saved") == [{"service": "_sip", "proto": "_tcp - Stream", "host": "_sip", "prio": "0",
                                     "weight": "5", "port": "5060", "content": "sip.example.net",
                                     "ttl": DEFAULT_TTL}]
    assert log(editor, "clicks") == ["addBtn", "saveAdd"]


def test_add_checkbox_field_is_set_by_its_boolean(editor):
    plan = plan_for(editor, "add", "CHK", host="flag", content="v.example.net", fields={"enabled": "yes"})
    w._add(editor, plan, DOMAIN)
    assert log(editor, "saved") == [{"host": "flag", "content": "v.example.net", "enabled": True,
                                     "ttl": DEFAULT_TTL}]


def test_a_type_that_does_not_settle_raises_before_any_field_is_filled(editor):
    plan = dict(plan_for(editor, "add", "MX", host="mail", content="mx.example.net", prio="10"), type="URL")
    with pytest.raises(w.WriteStepError) as caught:
        w._add(editor, plan, DOMAIN)
    assert caught.value.step == "add_type"
    assert log(editor, "saved") is None
    assert log(editor, "clicks") == ["addBtn"]


# --- The CAA flag: disabled on the add form and on the edit form, placeholder "0" on both --------------

def test_legacy_caa_add_plans_and_fills_with_the_disabled_flag_left_at_its_default(editor):
    plan = plan_for(editor, "add", "CAA", host="www", content="0 issue letsencrypt.org")
    assert "refused" not in plan
    w._add(editor, plan, DOMAIN)
    assert log(editor, "saved") == [{"host": "www", "flag": "", "tag": "issue",
                                     "provider": "letsencrypt.org", "ttl": DEFAULT_TTL}]
    assert log(editor, "clicks") == ["addBtn", "saveAdd"]


def test_a_flag_value_other_than_the_default_is_refused_by_the_plan(editor):
    assert plan_for(editor, "add", "CAA", host="www", content="1 issue letsencrypt.org") == {
        "refused": "field_disabled"}


def test_a_disabled_flag_with_another_value_is_refused_at_the_page_step_before_save(editor):
    plan = plan_for(editor, "add", "CAA", host="www", content="0 issue letsencrypt.org")
    plan["values"]["flag"] = "1"
    with pytest.raises(w.WriteStepError) as caught:
        w._add(editor, plan, DOMAIN)
    assert caught.value.step == "field_disabled"
    assert log(editor, "clicks") == ["addBtn"]
    assert log(editor, "saved") is None


# --- Update: the edit form takes the schema's fields; a disabled CAA flag is skipped when unchanged -------

def caa_update(page, **kw):
    return plan_for(page, "update", "CAA", rows=caa_rows(), host="@", expect="0 issue letsencrypt.org", **kw)


def test_update_fills_the_edit_form_and_skips_the_disabled_flag_with_the_same_value(editor):
    plan = caa_update(editor, content="0 issue sectigo.com")
    w._change(editor, plan, DOMAIN)
    assert log(editor, "clicks") == ["editRow", "saveEdit"]
    assert log(editor, "edited") == [{"host": "@", "flag": "0", "tag": "issue", "provider": "sectigo.com",
                                      "ttl": DEFAULT_TTL}]


def test_an_edit_flag_value_other_than_the_default_is_refused_by_the_plan(editor):
    assert caa_update(editor, content="1 issue sectigo.com") == {"refused": "field_disabled"}


def test_a_disabled_edit_flag_with_another_value_raises_at_the_page_step_before_any_click(editor):
    plan = caa_update(editor, content="0 issue sectigo.com")
    plan["values"]["flag"] = "1"
    with pytest.raises(w.WriteStepError) as caught:
        w._change(editor, plan, DOMAIN)
    assert caught.value.step == "field_disabled"
    assert log(editor, "clicks") == ["editRow"]
    assert log(editor, "edited") is None


# --- Round 2: a disabled required field is never the caller's; an optional host may be empty -----------

def test_caa_fields_only_add_plans_and_fills_without_the_disabled_flag(editor):
    plan = plan_for(editor, "add", "CAA", host="www", fields={"tag": "issue", "provider": "letsencrypt.org"})
    assert "refused" not in plan
    w._add(editor, plan, DOMAIN)
    assert log(editor, "saved") == [{"host": "www", "flag": "", "tag": "issue",
                                     "provider": "letsencrypt.org", "ttl": DEFAULT_TTL}]
    assert log(editor, "clicks") == ["addBtn", "saveAdd"]


def test_caa_with_nothing_is_refused_naming_exactly_tag_and_provider(editor):
    assert plan_for(editor, "add", "CAA", host="www") == {"refused": "missing_field",
                                                          "missing": ["tag", "provider"]}


def test_an_optional_empty_selector_leaves_the_host_input_unfilled(editor):
    plan = plan_for(editor, "add", "DMARC", host="", fields={"policy": "none"})
    assert plan["host"] == "@" and plan["fill_host"] is False
    w._add(editor, plan, DOMAIN)
    assert log(editor, "saved") == [{"host": "", "policy": "none", "ttl": DEFAULT_TTL}]
    assert log(editor, "clicks") == ["addBtn", "saveAdd"]


def test_a_required_host_still_refuses_an_empty_host(editor):
    assert plan_for(editor, "add", "MX", host="", content="mx.example.net", prio="10") == {"refused": "bad_host"}
