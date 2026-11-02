"""Schema and domain reads driven through a real offline Chrome. The account's domain list is served from
``list_page`` (the live list page's shape: "showing X out of Y total" text and two LOGIN links per domain),
the DNS editor from ``tests/fixtures/schema_model.html`` at ``index.php?LOGIN=<domain>``. The DNS home URL
answers with the list page, as the live panel does. Every request is recorded. Settle timing is scaled
down (SETTLE_MS 400, the model's late type renders after 1000 ms): a first read misses the late form and a
later read sees it.
"""
import json
from pathlib import Path

import pytest
from real_browser import DOMAIN_NAMES, chrome, list_page, make_page  # noqa: F401  (pytest fixtures)

import zoneedit_session as s

MODEL = (Path(__file__).parent / "fixtures" / "schema_model.html").read_text(encoding="utf-8")
PANEL_PREFIX = "https://cp.zoneedit.com/manage/domains/"
EDITOR_MARK = "/dns/index.php?LOGIN="
PLANTED = "PLANTED-TOKEN-7731"
TTL =["[DEF] 2 hours", "5 minutes", "10 minutes", "15 minutes", "30 minutes", "1 hour", "3 hours",
       "6 hours", "12 hours", "1 day", "2 days", "3 days", "1 week", "10 days", "2 weeks"]
TYPE_NAMES = ["A", "CNAME", "MX", "CAA", "TXT", "SRV", "DMARC", "URL"]
SWITCHES = {"validate_forwards": True, "adv_dns_records": False, "editor_bulk_save_mode": False,
            "editor_bulk_del_mode": True, "editor_search_live": True, "dyn_auth_token_enabled": False}


@pytest.fixture(autouse=True)
def quick_settle(monkeypatch):
    monkeypatch.setattr(s, "SETTLE_MS", 400)


@pytest.fixture
def editor(make_page):
    """Start a page whose panel requests are answered: the editor fixture for editor URLs, ``list_html``
    (default: the three domains) for everything else on the panel. Returns (page, requests)."""
    def start(list_html=None, editor_html=None):
        page = make_page()
        requests: list[str] = []
        served = list_html if list_html is not None else list_page()
        editor_served = editor_html if editor_html is not None else MODEL

        def handle(route):
            url = route.request.url
            requests.append(url)
            body = editor_served if EDITOR_MARK in url else served
            route.fulfill(status=200, content_type="text/html; charset=utf-8", body=body)

        page.context.route(lambda url: url.startswith(PANEL_PREFIX), handle)
        return page, requests

    return start


def field(name, label, kind, required=False, disabled=False, placeholder="", options=None):
    shaped = {"name": name, "label": label, "kind": kind, "required": required,
              "disabled": disabled, "placeholder": placeholder}
    if kind == "select":
        shaped["options"] = options
    return shaped


HOST = field("host", "Host", "text")
TTL_FIELD = field("ttl", "TTL", "select", options=TTL)
EXPECTED = {
    "A": [field("host", "Host", "text", required=True),
          field("content", "IP address", "text", required=True, placeholder="0.0.0.0"), TTL_FIELD],
    "CNAME": [HOST, field("content", "Target", "text", required=True), TTL_FIELD],
    "MX": [HOST, field("content", "Mail server", "text", required=True),
           field("prio", "Priority", "text", required=True), TTL_FIELD],
    "CAA": [HOST, field("flag", "Flag", "text", disabled=True),
            field("tag", "Tag", "select", options=["issue", "issuewild", "iodef"]),
            field("provider", "Provider", "select", options=["letsencrypt.org", "pki.goog", "sectigo.com"]),
            TTL_FIELD],
    "TXT": [HOST, field("content", "Text", "textarea", required=True), TTL_FIELD],
    "SRV": [field("service", "Service", "text"),
            field("proto", "Protocol", "select", options=["_tcp", "_udp"]), HOST,
            field("prio", "Priority", "text"), field("weight", "Weight", "text"),
            field("port", "Port", "text"), field("content", "Target", "text"), TTL_FIELD],
}
DMARC_POLICIES = [f"p{i}" for i in range(100)]


def log(page, key):
    """The model's log entries for ``key`` (a list), or None when nothing was logged."""
    return page.evaluate(
        f"(JSON.parse(document.documentElement.getAttribute('data-model-log') || '{{}}'))[{json.dumps(key)}] || null")


def editor_requests(requests):
    return [url for url in requests if EDITOR_MARK in url]


# --- the account's domain list -------------------------------------------------------------------------

def test_read_domains_lists_the_domains_in_page_order_with_total_and_complete(editor):
    page, _ = editor()
    assert s.read_domains(page) == {"domains": DOMAIN_NAMES, "total": 3, "complete": True, "default": None}


def test_a_duplicate_link_per_domain_is_counted_once(editor):
    # Each name has two links carrying the same LOGIN value: six links, three domains.
    page, _ = editor()
    result = s.read_domains(page)
    assert len(result["domains"]) == 3
    assert result["domains"] == DOMAIN_NAMES


def test_a_login_value_that_fails_valid_domain_is_dropped(editor):
    bad = ('<a href="https://cp.zoneedit.com/manage/domains/dns/index.php?LOGIN=Bad.Name">x</a>'
           '<a href="https://cp.zoneedit.com/manage/domains/dns/index.php?LOGIN=exa%20mple.com">x</a>'
           '<a href="https://cp.zoneedit.com/manage/domains/dns/index.php?LOGIN=">x</a>'
           '<a href="https://cp.zoneedit.com/manage/domains/dns/index.php?LOGIN=example.com%2Fx">x</a>')
    page, _ = editor(list_page(extra=bad))
    assert s.read_domains(page)["domains"] == DOMAIN_NAMES


def test_a_short_list_against_a_larger_total_is_not_complete(editor):
    # The count text says 4 out of 4 total but only three domains are linked.
    page, _ = editor(list_page(shown=4, total=4))
    result = s.read_domains(page)
    assert result["domains"] == DOMAIN_NAMES
    assert result["total"] == 4
    assert result["complete"] is False


def test_the_default_is_the_domain_only_for_a_single_domain_account(editor):
    page, _ = editor(list_page(["example.com"]))
    assert s.read_domains(page) == {"domains": ["example.com"], "total": 1, "complete": True,
                                    "default": "example.com"}


# --- open_domain: the empty name and the named domain --------------------------------------------------

def test_empty_name_with_several_domains_is_refused_and_no_editor_is_opened(editor):
    page, requests = editor()
    with pytest.raises(s.DomainRequired) as info:
        s.open_domain(page)
    assert info.value.domains == DOMAIN_NAMES
    assert editor_requests(requests) == []


def test_empty_name_with_one_domain_opens_that_domain(editor):
    page, requests = editor(list_page(["example.com"]))
    assert s.open_domain(page) == "example.com"
    assert any(EDITOR_MARK + "example.com" in url for url in editor_requests(requests))


def test_empty_name_with_zero_domains_is_unknown(editor):
    page, requests = editor(list_page([]))
    with pytest.raises(s.UnknownDomain) as info:
        s.open_domain(page)
    assert info.value.domains == []
    assert editor_requests(requests) == []


def test_open_domain_refuses_bad_syntax_without_any_navigation(editor):
    page, requests = editor()
    for bad in ["EXAMPLE.com", "example.com/", "example.com?x=1", "exa mple.com", "example", "example.com."]:
        with pytest.raises(ValueError, match="bad_domain"):
            s.open_domain(page, bad)
    assert requests == []


def test_open_domain_refuses_an_unknown_name_without_requesting_its_editor_url(editor):
    page, requests = editor()
    with pytest.raises(s.UnknownDomain) as info:
        s.open_domain(page, "missing.example.com")
    assert info.value.domains == DOMAIN_NAMES
    assert not any("LOGIN=missing.example.com" in url for url in requests)


def test_open_domain_always_opens_the_named_editor_url_and_verifies_it(editor):
    page, requests = editor()
    assert s.open_domain(page, "example.com") == "example.com"
    assert any(EDITOR_MARK + "example.com" in url for url in editor_requests(requests))
    assert s.open_domain(page, "example.net") == "example.net"
    assert any(EDITOR_MARK + "example.net" in url for url in editor_requests(requests))
    assert page.evaluate("document.querySelector('#selectDomain').selectedOptions[0].text") == "example.net"


def test_an_editor_showing_another_domain_is_unknown_and_nothing_is_read(editor, monkeypatch):
    # The editor answers the LOGIN URL for example.net but shows example.org selected.
    wrong = MODEL.replace("var wanted = new URLSearchParams(window.location.search).get('LOGIN');",
                          "var wanted = 'example.org';", 1)
    assert wrong != MODEL
    page, requests = editor(editor_html=wrong)
    content_reads = []
    real_content = page.content

    def counting_content():
        content_reads.append(True)
        return real_content()

    monkeypatch.setattr(page, "content", counting_content)
    with pytest.raises(s.UnknownDomain) as info:
        s.open_domain(page, "example.net")
    assert info.value.domains == DOMAIN_NAMES
    assert any(EDITOR_MARK + "example.net" in url for url in editor_requests(requests))
    with pytest.raises(s.UnknownDomain):
        s.read_schema(page, "example.net")
    with pytest.raises(s.UnknownDomain):
        s.read_pages(page, "example.net")
    assert log(page, "clicks") is None
    assert content_reads == []


def test_the_editor_is_never_opened_by_the_home_url_alone(editor):
    page, requests = editor()
    s.open_domain(page, "example.org")
    assert "https://cp.zoneedit.com/manage/domains/dns/" not in requests


# --- read_schema over the editor fixture ---------------------------------------------------------------

def test_read_schema_returns_every_type_with_exactly_the_model_fields(editor):
    page, _ = editor()
    result = s.read_schema(page, "example.com")
    assert result["type_names"] == TYPE_NAMES
    assert result["type_count"] == 8
    assert result["ttl_options"] == TTL
    assert result["unsettled"] == ["URL"]
    assert result["complete"] is False
    assert set(result["types"]) == set(EXPECTED) | {"DMARC"}
    for type_name, fields in EXPECTED.items():
        assert result["types"][type_name]["fields"] == fields, type_name
    dmarc = result["types"]["DMARC"]["fields"]
    assert [dmarc[0], dmarc[2]] == [HOST, TTL_FIELD]
    assert [f["name"] for f in dmarc] == ["host", "policy", "ttl"]


def test_hidden_fields_the_type_select_and_buttons_are_never_fields(editor):
    page, _ = editor()
    result = s.read_schema(page, "example.com")
    for type_name, shaped in result["types"].items():
        names = [f["name"] for f in shaped["fields"]]
        assert "type" not in names, type_name
        assert "csrf" not in names, type_name
        assert "legacy_weight" not in names, type_name


def test_long_option_lists_are_capped_with_their_total(editor):
    page, _ = editor()
    policy = s.read_schema(page, "example.com", "DMARC")["types"]["DMARC"]["fields"][1]
    assert policy["name"] == "policy"
    assert policy["options"] == DMARC_POLICIES[:80]
    assert policy["options_total"] == 100


def test_delayed_mx_form_is_read_after_its_late_render(editor):
    page, _ = editor()
    result = s.read_schema(page, "example.com", "mx")
    assert result["unsettled"] == []
    assert result["complete"] is True
    assert result["types"]["MX"]["fields"] == EXPECTED["MX"]


def test_a_type_that_never_renders_is_unsettled_with_no_guessed_fields(editor):
    page, _ = editor()
    result = s.read_schema(page, "example.com", "URL")
    assert result["unsettled"] == ["URL"]
    assert result["complete"] is False
    assert result["types"] == {}


def test_record_type_filter_returns_one_type_only(editor):
    page, _ = editor()
    result = s.read_schema(page, "example.com", "caa")
    assert list(result["types"]) == ["CAA"]
    assert result["types"]["CAA"]["fields"] == EXPECTED["CAA"]
    assert result["type_count"] == 8
    assert result["unsettled"] == []


def test_an_unknown_record_type_raises_with_the_offered_types(editor):
    page, _ = editor()
    with pytest.raises(s.UnknownRecordType) as info:
        s.read_schema(page, "example.com", "NS")
    assert info.value.types == TYPE_NAMES


def test_read_settings_returns_the_switch_map_and_the_paging_size(editor):
    page, _ = editor()
    s.open_domain(page, "example.com")
    assert s.read_settings(page) == {"switches": SWITCHES, "paging_size": "50"}


def test_the_planted_token_value_is_never_read_by_any_schema_result(editor):
    page, _ = editor()
    s.open_domain(page, "example.com")
    everything = [s.read_settings(page), s.read_schema(page, "example.com", "TXT")]
    assert PLANTED not in json.dumps(everything)


def test_the_model_log_shows_only_the_add_click_and_type_changes_never_a_submit(editor):
    page, _ = editor()
    s.read_schema(page, "example.com")
    assert log(page, "clicks") == ["addBtn"]
    assert log(page, "submits") is None
    assert set(log(page, "changes") or []) >= set(TYPE_NAMES[1:])
