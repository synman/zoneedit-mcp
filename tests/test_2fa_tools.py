"""Second-factor tools: the selftest second_factor and seed fields, twofa_status, twofa_latch_clear and
the live tool list. All offline: a fake patchright is installed per test, the clock and the seed are
injected, and the planted seed and the computed codes are canaries that must never reach a result."""
from __future__ import annotations

import asyncio
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

import zoneedit_server as srv
import zoneedit_session as s
import zoneedit_tools as t
from zoneedit_totp import totp
from zoneedit_vault import TOTP_SEED_KEY, VaultError

FIXTURE_HTML = (Path(__file__).parent / "fixtures" / "dns_index.html").read_text(encoding="utf-8")
SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
PLANTED_SEED = "JBSWY3DPEHPK3PXP"
HOME = "https://cp.zoneedit.com/manage/home/"
TFA = "https://cp.zoneedit.com/tfa.php"
LOGIN_ERR = "https://cp.zoneedit.com/login.php?err=1"
NOW = 1_000_000_010.0          # 20 s into a 30 s step: 10 s left, enough for a code without a wait


@pytest.fixture(autouse=True)
def _reset_state():
    s._BLOCKED_UNTIL = 0.0
    s._LAST_SUBMITTED_COUNTER = None
    s._LAST_SECOND_FACTOR = None
    yield
    s._BLOCKED_UNTIL = 0.0
    s._LAST_SUBMITTED_COUNTER = None
    s._LAST_SECOND_FACTOR = None


@pytest.fixture
def clock(monkeypatch):
    """Fake clock: ``_clock`` for the latch (monotonic 100 s) and ``time.time`` for the TOTP window."""
    state = {"mono": 100.0, "now": NOW}
    monkeypatch.setattr(s, "_clock", lambda: state["mono"])
    monkeypatch.setattr(s, "time", SimpleNamespace(time=lambda: state["now"],
                                                   monotonic=lambda: state["mono"]))
    return state


@pytest.fixture
def seed_calls(monkeypatch):
    """Both seed readers (the login's answer and the tools) return SEED and count their calls."""
    calls = []

    def fake():
        calls.append(1)
        return SEED
    monkeypatch.setattr(s, "get_totp_seed", fake)
    monkeypatch.setattr(t, "get_totp_seed", fake)
    return calls


def _install_patchright(monkeypatch, sync_playwright):
    api = types.ModuleType("patchright.sync_api")
    api.sync_playwright = sync_playwright
    package = types.ModuleType("patchright")
    package.sync_api = api
    monkeypatch.setitem(sys.modules, "patchright", package)
    monkeypatch.setitem(sys.modules, "patchright.sync_api", api)


class _Keyboard:
    def __init__(self, page):
        self.page = page

    def press(self, key):
        self.page.events.append(("press", key))


class _Loc:
    def __init__(self, page, selector):
        self.page = page
        self.selector = selector

    @property
    def first(self):
        return self

    def fill(self, value, timeout=None):
        self.page.events.append(("fill", self.selector, value))

    def click(self, timeout=None):
        self.page.events.append(("click", self.selector))
        if self.selector == s.SUBMIT_BUTTON and self.page.next_urls:
            self.page.url = self.page.next_urls.pop(0)

    def count(self):
        return 1

    def is_checked(self, timeout=None):
        return False          # the bulk-save switch is unchecked, so bulk_save_off is True


class FakePage:
    """A page whose URL changes on each submit click, from ``next_urls``."""

    def __init__(self, next_urls, clock):
        self.url = s.LOGIN_URL
        self.next_urls = list(next_urls)
        self.events = []
        self.keyboard = _Keyboard(self)
        self.clock = clock

    def goto(self, url, wait_until=None):
        self.events.append(("goto", url))

    def wait_for_timeout(self, ms):
        self.events.append(("wait", ms))
        self.clock["now"] += ms / 1000

    def wait_for_load_state(self, state=None):
        pass

    def wait_for_function(self, expression, timeout=None):
        pass

    def wait_for_selector(self, selector, timeout=None):
        pass

    def evaluate(self, js):
        # The account holds one domain, and the editor opened shows it selected.
        if js == s.DOMAIN_LIST_JS:
            return {"logins": ["example.com", "example.com"], "total": 1}
        if js == s.EDITOR_SELECTED_JS:
            return "example.com"
        raise AssertionError("unexpected page script in a second-factor test")

    def locator(self, selector):
        return _Loc(self, selector)

    def content(self):
        return FIXTURE_HTML


class Harness:
    def __init__(self):
        self.launches = 0
        self.closed = 0
        self.next_urls = []
        self.page = None


@pytest.fixture
def harness(monkeypatch, clock, seed_calls):
    h = Harness()

    class _Browser:
        def new_context(self, **kwargs):
            return _Context()

        def close(self):
            h.closed += 1

    class _Context:
        def new_page(self):
            h.page = FakePage(h.next_urls, clock)
            return h.page

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

    def sync_playwright():
        h.launches += 1
        return _CM()

    _install_patchright(monkeypatch, sync_playwright)
    monkeypatch.setattr(s, "get_credentials", lambda: ("user", "pw"))
    return h


@pytest.fixture
def launches(monkeypatch):
    """A browser launch is recorded and fails loudly, so a path that reaches it cannot pass."""
    calls = []

    def sync_playwright():
        calls.append(1)
        raise AssertionError("a second-factor tool launched a browser")

    _install_patchright(monkeypatch, sync_playwright)
    monkeypatch.setattr(s, "get_credentials", lambda: ("user", "pw"))
    return calls


def _read_url(page):
    return page.url


# (a) selftest after a password-only login

def test_a_password_only_login_reports_not_asked_and_never_reads_seed(harness, seed_calls):
    harness.next_urls = [HOME]
    result = t.selftest(runner=s.run)
    assert result == {
        "login": "ok",
        "domain": "example.com",
        "dns_page": True,
        "panel_total": 28,
        "pages": 3,
        "bulk_save_off": True,
        "second_factor": "not_asked",
        "seed": "not_read",
    }
    assert seed_calls == []
    assert (harness.launches, harness.closed) == (1, 1)


# (b) selftest after a login that meets the code page

def test_b_code_page_reports_answered_and_seed_present(harness, seed_calls):
    harness.next_urls = [TFA, HOME]
    result = t.selftest(runner=s.run)
    assert result["second_factor"] == "answered"
    assert result["seed"] == "present"
    assert len(seed_calls) == 2          # one read for the code answer, one for the selftest's presence check
    assert len([e for e in harness.page.events if e[0] == "fill" and e[1] == s.CODE_INPUT]) == 1


# (c) seed missing: the selftest failure result is unchanged

def test_c_missing_seed_leaves_the_failure_result_unchanged(harness, monkeypatch):
    def missing():
        raise VaultError(f"vault_miss:{TOTP_SEED_KEY}")
    monkeypatch.setattr(s, "get_totp_seed", missing)
    monkeypatch.setattr(t, "get_totp_seed", missing)
    harness.next_urls = [TFA]
    assert t.selftest(runner=s.run) == {"ok": False, "error_type": "second_factor_required"}
    assert s._BLOCKED_UNTIL == 0.0       # a missing seed never latches


def test_c2_seed_unreadable_after_an_answered_code_reports_absent(harness, monkeypatch):
    def missing():
        raise VaultError(f"vault_miss:{TOTP_SEED_KEY}")
    monkeypatch.setattr(t, "get_totp_seed", missing)
    harness.next_urls = [TFA, HOME]
    result = t.selftest(runner=s.run)
    assert (result["second_factor"], result["seed"]) == ("answered", "absent")


# (d) twofa_status

def test_d_status_with_no_latch_reports_a_clean_state(clock, seed_calls):
    assert t.twofa_status() == {
        "seed": "present",
        "last_second_factor": None,
        "latch_seconds_left": 0,
        "last_submitted_step": None,
        "step_seconds_left": 10,
        "epoch": int(NOW),
    }


def test_d_status_with_a_latch_reports_the_seconds_left(clock, seed_calls):
    s._BLOCKED_UNTIL = clock["mono"] + 300
    assert t.twofa_status()["latch_seconds_left"] == 300


@pytest.mark.parametrize("message, expected", [
    (f"vault_miss:{TOTP_SEED_KEY}", "absent"),
    (f"vault_unavailable:{TOTP_SEED_KEY}:OSError", "absent"),
    (f"vault_seed_invalid:{TOTP_SEED_KEY}", "invalid"),
    (f"vault_field_missing:{TOTP_SEED_KEY}", "invalid"),
])
def test_d_seed_status_follows_the_vault_message(clock, monkeypatch, message, expected):
    def raising():
        raise VaultError(message)
    monkeypatch.setattr(t, "get_totp_seed", raising)
    assert t.twofa_status()["seed"] == expected


def test_d_status_launches_nothing_and_leaks_no_seed_or_code(clock, launches, monkeypatch):
    monkeypatch.setattr(t, "get_totp_seed", lambda: PLANTED_SEED)
    monkeypatch.setattr(s, "_LAST_SECOND_FACTOR", "answered")
    s._BLOCKED_UNTIL = clock["mono"] + 300
    result = t.twofa_status()
    code = totp(PLANTED_SEED, NOW)
    assert launches == []
    assert result["seed"] == "present"
    assert PLANTED_SEED not in repr(result)
    assert code not in [str(value) for value in result.values()]


# (e) twofa_latch_clear

def test_e_preview_changes_nothing(clock):
    s._BLOCKED_UNTIL = clock["mono"] + 300
    assert t.twofa_latch_clear(False) == {
        "ok": True, "confirmed": False, "latch_seconds_left": 300, "action": "clear_latch"}
    assert s._BLOCKED_UNTIL == 400.0


def test_e_confirmed_clears_and_returns_the_seconds_left(clock):
    s._BLOCKED_UNTIL = clock["mono"] + 300
    assert t.twofa_latch_clear(True) == {
        "ok": True, "confirmed": True, "cleared_seconds": 300, "action": "clear_latch"}
    assert s._BLOCKED_UNTIL == 0.0
    assert t.twofa_latch_clear(True)["cleared_seconds"] == 0


def test_e_a_run_after_the_clear_is_no_longer_latched(harness, clock):
    harness.next_urls = [LOGIN_ERR]
    with pytest.raises(s.LoginFailed):
        s.run(_read_url)
    with pytest.raises(s.LoginLatched):
        s.run(_read_url)
    assert t.twofa_latch_clear(True)["cleared_seconds"] == s.LATCH_S
    harness.next_urls = [HOME]
    assert s.run(_read_url) == HOME


# (f) the live tool list

def _ann(annotations, key):
    return annotations.get(key) if isinstance(annotations, dict) else getattr(annotations, key)


def test_every_run_forgets_the_last_second_factor_before_anything_else(clock):
    s._LAST_SECOND_FACTOR = "answered"
    s._BLOCKED_UNTIL = clock["mono"] + 60
    with pytest.raises(s.LoginLatched):
        s._run_body(lambda page: None)
    assert s._LAST_SECOND_FACTOR is None
    assert t.twofa_status()["last_second_factor"] is None


def test_f_live_tool_list_declares_both_second_factor_tools():
    server = srv.register_tools(srv.build_server())
    tools = {tool.name: tool for tool in asyncio.run(server.list_tools())}
    status, latch = tools["zoneedit_2fa_status"], tools["zoneedit_2fa_latch_clear"]
    assert _ann(status.annotations, "title") == "ZoneEdit 2FA Status"
    assert _ann(status.annotations, "readOnlyHint") is True
    assert _ann(latch.annotations, "title") == "ZoneEdit Clear Login Latch"
    assert _ann(latch.annotations, "readOnlyHint") is False
    assert (status.inputSchema or {}).get("properties", {}) == {}
    props = latch.inputSchema["properties"]
    assert set(props) == {"confirmed"}
    assert props["confirmed"]["type"] == "boolean"
    assert props["confirmed"].get("default") is False
    assert props["confirmed"]["description"].strip()
    new = {"zoneedit_2fa_status", "zoneedit_2fa_latch_clear"}
    guarded_new = {name for name in new if "confirmed" in (tools[name].inputSchema or {}).get("properties", {})}
    assert guarded_new == {"zoneedit_2fa_latch_clear"}
    assert "WRITE GUARD:" in latch.description
    assert "WRITE GUARD:" not in status.description
