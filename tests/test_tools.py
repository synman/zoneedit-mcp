import asyncio
import json
import sys
import types
from pathlib import Path

import pytest

import zoneedit_server as srv
import zoneedit_session as s
import zoneedit_tools as t
import zoneedit_vault as v

FIXTURE_HTML = (Path(__file__).parent / "fixtures" / "dns_index.html").read_text(encoding="utf-8")


def _row(type_, host, content, h="h"):
    return (f'<div class="item-wrapped row" data-hash="{h}">'
            f'<div class="col border-end item col-md-2">{type_}</div>'
            f'<div class="col col-md-4 border-end item">{host}</div>'
            f'<div class="col border-end item col-md-4"><span class="rdata">{content}</span></div>'
            f'<div class="col-md-1 col item">[DEF]&nbsp;2&nbsp;hours</div></div>')


def _page(rows, total, pages):
    labels = "".join(f'<li class="page-item"><a>{n}</a></li>' for n in range(1, pages + 1))
    nav = (f'<nav aria-label="DNS pagination"><div>Total: {total}</div>'
           f'<ul class="pagination">{labels}</ul></nav>')
    return "<html><body>" + nav + "".join(rows) + "</body></html>"


def _fake(pages):
    return lambda read: pages


def _records_fake(pages, domain="example.com"):
    """A records runner: the domain that was read, with its pages (the read returns both)."""
    return lambda read: (domain, pages)


def _raise(exc):
    def runner(read):
        raise exc
    return runner


def test_records_complete_read():
    pages = [_page([_row("A", "@", "1.2.3.4"), _row("A", "www", "1.2.3.5")], total=2, pages=1)]
    result = t.records(runner=_records_fake(pages))
    assert result["complete"] is True
    assert (result["read"], result["panel_total"]) == (2, 2)
    assert (result["pages_read"], result["pages_expected"]) == (1, 1)
    assert result["matched"] == 2
    assert "warning" not in result


def test_records_incomplete_rows_warns():
    pages = [_page([_row("A", "@", "1.2.3.4"), _row("A", "www", "1.2.3.5")], total=5, pages=1)]
    result = t.records(runner=_records_fake(pages))
    assert result["complete"] is False
    assert "Incomplete" in result["warning"]


def test_records_incomplete_pages_warns():
    pages = [_page([_row("A", "@", "1.2.3.4")], total=1, pages=2)]
    result = t.records(runner=_records_fake(pages))
    assert result["complete"] is False
    assert (result["pages_read"], result["pages_expected"]) == (1, 2)


def test_host_filter_keeps_exact_matches_only():
    pages = [_page([_row("A", "@", "1.2.3.4"), _row("A", "www", "1.2.3.5")], total=2, pages=1)]
    result = t.records("www", runner=_records_fake(pages))
    assert [r["host"] for r in result["records"]] == ["www"]
    assert (result["read"], result["panel_total"], result["matched"]) == (2, 2, 1)
    assert result["filter"] == "www"
    assert [r["host"] for r in t.records("@", runner=_records_fake(pages))["records"]] == ["@"]


def test_host_filter_with_no_match_keeps_totals():
    pages = [_page([_row("A", "@", "1.2.3.4")], total=1, pages=1)]
    result = t.records("nope", runner=_records_fake(pages))
    assert result["matched"] == 0
    assert (result["read"], result["panel_total"]) == (1, 1)


def test_empty_zone_says_what_it_covered():
    result = t.records(runner=_records_fake([_page([], total=0, pages=1)]))
    assert result["records"] == []
    assert "Zero records" in result["warning"]
    assert result["pages_read"] == 1


def test_fixture_page_alone_is_incomplete_against_three_pages():
    result = t.records(runner=_records_fake([FIXTURE_HTML]))
    assert (result["read"], result["panel_total"]) == (10, 28)
    assert (result["pages_read"], result["pages_expected"]) == (1, 3)
    assert result["complete"] is False


def test_selftest_ok_from_fixture(monkeypatch):
    monkeypatch.setattr(s, "_LAST_SECOND_FACTOR", None)
    assert t.selftest(runner=_fake((FIXTURE_HTML, True, "example.com"))) == {
        "login": "ok",
        "domain": "example.com",
        "dns_page": True,
        "panel_total": 28,
        "pages": 3,
        "bulk_save_off": True,
        "second_factor": "unknown",
        "seed": "not_read",
    }


def test_selftest_second_factor():
    assert t.selftest(runner=_raise(s.SecondFactorRequired())) == {
        "ok": False, "error_type": "second_factor_required"}


def test_selftest_login_failed():
    assert t.selftest(runner=_raise(s.LoginFailed())) == {
        "ok": False, "error_type": "login_failed"}


def test_selftest_other_error_returns_type_name_only():
    def boom(read):
        raise ValueError("sensitive detail")

    result = t.selftest(runner=boom)
    assert result == {"ok": False, "error_type": "ValueError"}
    assert "sensitive" not in repr(result)


def test_safe_error_returns_type_name_only():
    assert t.safe_error(ValueError("secret")) == "ValueError"
    assert t.safe_error(s.SessionError("TimeoutError", "https://cp.zoneedit.com/x")) == "TimeoutError"


def test_live_server_lists_read_and_write_tools():
    server = srv.register_tools(srv.build_server())
    tools = {tool.name: tool for tool in asyncio.run(server.list_tools())}

    def get(annotations, key):
        return annotations.get(key) if isinstance(annotations, dict) else getattr(annotations, key)

    assert set(tools) == {"zoneedit_records", "zoneedit_selftest", "zoneedit_2fa_status",
                          "zoneedit_domains", "zoneedit_schema",
                          "zoneedit_2fa_latch_clear", "zoneedit_record_add",
                          "zoneedit_record_update", "zoneedit_record_delete"}
    titles = [get(tool.annotations, "title") for tool in tools.values()]
    assert len(set(titles)) == len(titles)
    assert get(tools["zoneedit_records"].annotations, "title") == "ZoneEdit Records"
    assert get(tools["zoneedit_selftest"].annotations, "title") == "ZoneEdit Self-Test"
    assert get(tools["zoneedit_domains"].annotations, "title") == "ZoneEdit Domains"
    assert get(tools["zoneedit_schema"].annotations, "title") == "ZoneEdit Record Schema"
    for name in ("zoneedit_records", "zoneedit_selftest", "zoneedit_2fa_status",
                 "zoneedit_domains", "zoneedit_schema"):
        assert get(tools[name].annotations, "readOnlyHint") is True
    for name in ("zoneedit_record_add", "zoneedit_record_update", "zoneedit_record_delete",
                 "zoneedit_2fa_latch_clear"):
        assert get(tools[name].annotations, "title").startswith("ZoneEdit ")
        assert get(tools[name].annotations, "readOnlyHint") is False


def test_host_filter_is_exact_equality_on_fixture():
    assert [r["host"] for r in t.records("meet", runner=_records_fake([FIXTURE_HTML]))["records"]] == ["meet"]
    assert [r["host"] for r in t.records("@", runner=_records_fake([FIXTURE_HTML]))["records"]] == ["@"]
    assert t.records("me", runner=_records_fake([FIXTURE_HTML]))["records"] == []


class _Locator:
    def __init__(self, page, selector):
        self._page = page
        self._selector = selector

    @property
    def first(self):
        return self

    def fill(self, value, timeout=None):
        self._page.events.append(("fill", self._selector))

    def click(self, timeout=None):
        self._page.events.append(("click", self._selector))


class _Page:
    def __init__(self, url):
        self.url = url
        self.events = []

    def goto(self, url, wait_until=None):
        self.events.append(("goto", url))

    def wait_for_timeout(self, ms):
        pass

    def wait_for_load_state(self, state=None):
        pass

    def locator(self, selector):
        return _Locator(self, selector)


def test_login_tfa_url_raises_second_factor():
    with pytest.raises(s.SecondFactorRequired):
        s.login(_Page("https://cp.zoneedit.com/tfa.php"), "user", "pw")


def test_login_login_url_raises_login_failed():
    with pytest.raises(s.LoginFailed):
        s.login(_Page("https://cp.zoneedit.com/login.php?err=1"), "user", "pw")


def test_login_ordinary_url_returns_and_clicks_submit_once():
    page = _Page("https://cp.zoneedit.com/home/")
    assert s.login(page, "user", "pw") is None
    assert len([e for e in page.events if e[0] == "click"]) == 1


LEAK_CANARY = "hunter2-SECRET-VALUE"


def _install_fake_patchright(monkeypatch, closed):
    class _Context:
        def new_page(self):
            return _Page("https://cp.zoneedit.com/manage/x?LOGIN=example.com&tok=ABC")

    class _Browser:
        def new_context(self, **kwargs):
            return _Context()

        def close(self):
            closed.append(True)

    class _Chromium:
        def launch(self, **kwargs):
            return _Browser()

    class _Playwright:
        chromium = _Chromium()

    class _CM:
        def __enter__(self):
            return _Playwright()

        def __exit__(self, *exc):
            return False

    sync_api = types.ModuleType("patchright.sync_api")
    sync_api.sync_playwright = lambda: _CM()
    monkeypatch.setitem(sys.modules, "patchright", types.ModuleType("patchright"))
    monkeypatch.setitem(sys.modules, "patchright.sync_api", sync_api)


def test_run_error_keeps_only_type_and_url(monkeypatch):
    closed = []
    _install_fake_patchright(monkeypatch, closed)
    monkeypatch.setattr(s, "get_credentials", lambda: ("user", "pw"))

    def reader(page):
        raise RuntimeError(f"filled value {LEAK_CANARY} in call log")

    with pytest.raises(s.SessionError) as info:
        s.run(reader)
    err = info.value
    assert err.error_type == "RuntimeError"
    assert err.url == "https://cp.zoneedit.com/manage/x"
    assert LEAK_CANARY not in str(err)
    assert all(LEAK_CANARY not in str(value) for value in vars(err).values())
    assert err.__context__ is None
    assert closed == [True]


def test_two_field_vault_object_picks_field_for_each_key(monkeypatch):
    payloads = {
        v.USERNAME_KEY: json.dumps({"username": "shell", "password": "WRONG-FIELD"}),
        v.PASSWORD_KEY: json.dumps({"username": "shell", "password": "real-pw"}),
    }
    monkeypatch.setattr(v, "get_secret", lambda key: payloads[key])
    assert v.get_credentials() == ("shell", "real-pw")


def test_raw_vault_values_are_used_as_is(monkeypatch):
    payloads = {v.USERNAME_KEY: "shell", v.PASSWORD_KEY: "real-pw"}
    monkeypatch.setattr(v, "get_secret", lambda key: payloads[key])
    assert v.get_credentials() == ("shell", "real-pw")


def test_concurrent_runs_never_overlap_in_the_browser_block(monkeypatch):
    import threading
    import time

    closed = []
    _install_fake_patchright(monkeypatch, closed)
    monkeypatch.setattr(s, "get_credentials", lambda: ("user", "pw"))

    counter_lock = threading.Lock()
    state = {"inside": 0, "max": 0, "runs": 0}

    def reader(page):
        with counter_lock:
            state["inside"] += 1
            state["max"] = max(state["max"], state["inside"])
        time.sleep(0.05)
        with counter_lock:
            state["inside"] -= 1
            state["runs"] += 1

    threads = [threading.Thread(target=s.run, args=(reader,)) for _ in range(3)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert state["runs"] == 3
    assert state["max"] == 1


# Dynamic reads: domains, schema, and the records domain option. Fake runners only, no browser.

DOMAINS = ["example.com", "example.net", "example.org"]


def _fake_result(value):
    return lambda read: value


def _domains_state(read):
    return {"domains": DOMAINS, "default": None, "total": 3, "complete": True}


def test_domains_tool_shape_from_the_runner():
    assert t.domains(runner=_domains_state) == {"domains": DOMAINS, "default": None, "count": 3,
                                                "total": 3, "complete": True}


def test_schema_refuses_an_empty_domain_when_several_exist_with_the_list():
    result = t.schema("", runner=_fake_result(s.DomainRequired(DOMAINS)))
    assert result == {"ok": False, "refused": "domain_required", "domains": DOMAINS}


def test_schema_tool_returns_the_read_schema_dict_unchanged():
    shaped = {"domain": "example.com", "type_names": ["A"], "types": {}, "ttl_options": [],
              "settings": {"switches": {}, "paging_size": None}, "type_count": 1,
              "unsettled": [], "complete": True}
    assert t.schema("example.com", "", runner=_fake_result(shaped)) == shaped


def test_schema_refuses_a_bad_domain_before_any_runner_call():
    def runner(read):
        raise AssertionError("the runner must not be called for a bad domain")

    assert t.schema("EXAMPLE.com", runner=runner) == {"ok": False, "refused": "bad_domain"}


def test_schema_refuses_an_unknown_domain_with_the_account_list():
    result = t.schema("example.org", runner=_fake_result(s.UnknownDomain(DOMAINS)))
    assert result == {"ok": False, "refused": "unknown_domain", "domains": DOMAINS}


def test_schema_refuses_an_unknown_record_type_with_the_offered_types():
    result = t.schema("", "NS", runner=_fake_result(s.UnknownRecordType(["A", "MX"])))
    assert result == {"ok": False, "refused": "unknown_record_type", "types": ["A", "MX"]}


def test_records_with_an_empty_domain_reads_the_account_domain_and_reports_it(monkeypatch):
    seen = []

    def fake_read_pages_domain(page, domain=""):
        seen.append((page, domain))
        return "example.com", [FIXTURE_HTML]

    monkeypatch.setattr(t, "read_pages_domain", fake_read_pages_domain)
    result = t.records("meet", runner=lambda read: read("PAGE"))
    assert seen == [("PAGE", "")]
    assert result["domain"] == "example.com"
    assert [r["host"] for r in result["records"]] == ["meet"]


def test_records_passes_a_named_domain_to_the_read_and_reports_it(monkeypatch):
    seen = []

    def fake_read_pages_domain(page, domain=""):
        seen.append(domain)
        return domain, [FIXTURE_HTML]

    monkeypatch.setattr(t, "read_pages_domain", fake_read_pages_domain)
    result = t.records("", "example.net", runner=lambda read: read("PAGE"))
    assert seen == ["example.net"]
    assert result["domain"] == "example.net"


def test_records_refuses_a_bad_domain_and_an_unknown_domain():
    def never(read):
        raise AssertionError("the runner must not be called for a bad domain")

    assert t.records("", "Example.net", runner=never) == {"ok": False, "refused": "bad_domain",
                                                          "domain": None}
    assert t.records("", "example.org", runner=_fake_result(s.UnknownDomain(DOMAINS))) == {
        "ok": False, "refused": "unknown_domain", "domains": DOMAINS, "domain": None}


def test_records_with_several_domains_and_none_named_is_domain_required():
    assert t.records("", runner=_fake_result(s.DomainRequired(DOMAINS))) == {
        "ok": False, "refused": "domain_required", "domains": DOMAINS, "domain": None}


@pytest.mark.parametrize("name, good", [
    ("example.com", True), ("a.b", True), ("my-host.example.net", True), ("x1.example.org", True),
    ("a" * 63 + ".example.com", True),
    ("EXAMPLE.com", False), ("example.com.", False), ("example.com/x", False),
    ("example.com?LOGIN=x", False), ("exa mple.com", False), ("example", False), ("", False),
    ("a" * 64 + ".example.com", False), ("-bad.example.com", False), ("bad-.example.com", False),
    ("ex..ample.com", False), ("https://example.com", False), ("a" * 254, False), (None, False),
])
def test_valid_domain_table(name, good):
    assert s.valid_domain(name) is good


def test_dns_url_for_refuses_before_any_navigation():
    with pytest.raises(ValueError, match="bad_domain"):
        s.dns_url_for("Example.com")
    page = _Page("about:blank")
    with pytest.raises(ValueError, match="bad_domain"):
        s.open_domain(page, "example.com/x")
    assert page.events == []


def test_dns_url_for_builds_the_login_url_for_a_good_name():
    assert s.dns_url_for("example.net") == (
        "https://cp.zoneedit.com/manage/domains/dns/index.php?LOGIN=example.net")
