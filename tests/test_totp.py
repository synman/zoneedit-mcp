"""TOTP: the pure RFC 6238 module, the vault seed accessor, the second-factor session path and the
selftest mapping. All offline. No real browser: a fake patchright is installed per test, and the
clock and the seed are injected. The seed and the codes are canaries; none may appear in an
exception or a returned value."""
from __future__ import annotations

import sys
import time
import types
from types import SimpleNamespace

import pytest

import zoneedit_session as s
import zoneedit_tools as t
import zoneedit_vault as v
from zoneedit_totp import seconds_left, totp
from zoneedit_vault import VaultError

RFC_SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"          # base32 of b"12345678901234567890"
SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
TOTP_KEY = v.TOTP_SEED_KEY
HOME = "https://cp.zoneedit.com/manage/home/"
TFA = "https://cp.zoneedit.com/tfa.php"
LOGIN_ERR = "https://cp.zoneedit.com/login.php?err=1"
NOW = 1_000_000_010.0          # 20 s into a step: no wait needed


# --- Pure module -------------------------------------------------------------------------------

@pytest.mark.parametrize("at, expected", [
    (59, "287082"),
    (1111111109, "081804"),
    (1111111111, "050471"),
    (1234567890, "005924"),
    (2000000000, "279037"),
    (20000000000, "353130"),
])
def test_rfc6238_sha1_vectors(at, expected):
    assert totp(RFC_SEED, at) == expected


def test_normalisation_gives_the_same_code():
    expected = totp(RFC_SEED, 59)
    assert totp(RFC_SEED.lower(), 59) == expected
    assert totp("GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ", 59) == expected
    assert totp("GEZD-GNBV-GY3T-QOJQ-GEZD-GNBV-GY3T-QOJQ", 59) == expected


def test_missing_padding_is_rebuilt():
    assert totp("MZXW6YQ", NOW) == totp("MZXW6YQ=", NOW) == totp("mzxw6yq", NOW)


@pytest.mark.parametrize("bad", ["!!!", "1", "   -  ", ""])
def test_invalid_seed_raises_without_the_seed_in_the_message(bad):
    with pytest.raises(ValueError) as info:
        totp(bad, 0)
    assert str(info.value) == "invalid_seed"
    assert bad.strip() == "" or bad not in str(info.value)


def test_seconds_left_edges():
    assert seconds_left(0) == 30
    assert seconds_left(29) == 1
    assert seconds_left(30) == 30          # exactly on a boundary: a full step left
    assert seconds_left(29.5) == pytest.approx(0.5)
    assert seconds_left(45, step=60) == 15
    assert seconds_left(59.999, step=60) == pytest.approx(0.001)


# --- Vault seed accessor -----------------------------------------------------------------------

def _vault(monkeypatch, raw=None, exc=None):
    def fake(key):
        assert key == TOTP_KEY
        if exc is not None:
            raise exc
        return raw
    monkeypatch.setattr(v, "get_secret", fake)


def test_vault_raw_seed(monkeypatch):
    _vault(monkeypatch, raw=SEED)
    assert v.get_totp_seed() == SEED


def test_vault_raw_seed_is_stripped(monkeypatch):
    _vault(monkeypatch, raw=f"  {SEED}  ")
    assert v.get_totp_seed() == SEED


def test_vault_json_seed_field(monkeypatch):
    _vault(monkeypatch, raw='{"seed": "%s"}' % SEED)
    assert v.get_totp_seed() == SEED


def test_vault_json_value_field(monkeypatch):
    _vault(monkeypatch, raw='{"value": "%s"}' % SEED)
    assert v.get_totp_seed() == SEED


def test_vault_json_checks_seed_before_value(monkeypatch):
    _vault(monkeypatch, raw='{"seed": "%s", "value": "NOT!VALID"}' % SEED)
    assert v.get_totp_seed() == SEED


def test_vault_json_with_neither_field_names_the_key_only(monkeypatch):
    _vault(monkeypatch, raw='{"other": "%s"}' % SEED)
    with pytest.raises(VaultError) as info:
        v.get_totp_seed()
    assert str(info.value) == f"vault_field_missing:{TOTP_KEY}"
    assert SEED not in str(info.value)


def test_vault_invalid_seed_names_the_key_only(monkeypatch):
    bad = "NOT!VALID"
    _vault(monkeypatch, raw=bad)
    with pytest.raises(VaultError) as info:
        v.get_totp_seed()
    assert str(info.value) == f"vault_seed_invalid:{TOTP_KEY}"
    assert bad not in str(info.value)


def test_vault_miss_propagates_the_key_only(monkeypatch):
    _vault(monkeypatch, exc=VaultError(f"vault_miss:{TOTP_KEY}"))
    with pytest.raises(VaultError) as info:
        v.get_totp_seed()
    assert str(info.value) == f"vault_miss:{TOTP_KEY}"


# --- Session: second factor, latch, leaks ------------------------------------------------------

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


class _Keyboard:
    def __init__(self, page):
        self.page = page

    def press(self, key):
        self.page.events.append(("press", key))


class FakePage:
    """A page whose URL changes on each submit click, from ``next_urls``."""

    def __init__(self, next_urls, clock=None):
        self.url = s.LOGIN_URL
        self.next_urls = list(next_urls)
        self.events = []
        self.keyboard = _Keyboard(self)
        self.clock = clock

    def goto(self, url, wait_until=None):
        self.events.append(("goto", url))

    def wait_for_timeout(self, ms):
        self.events.append(("wait", ms))
        if self.clock is not None:          # a wait moves the fake clock forward, as real time does
            self.clock["now"] += ms / 1000

    def wait_for_load_state(self, state=None):
        pass

    def locator(self, selector):
        return _Loc(self, selector)


class Harness:
    def __init__(self):
        self.launches = 0
        self.closed = 0
        self.next_urls = []
        self.page = None
        self.pages = []


@pytest.fixture(autouse=True)
def _reset_latch():
    s._BLOCKED_UNTIL = 0.0
    s._LAST_SUBMITTED_COUNTER = None
    yield
    s._BLOCKED_UNTIL = 0.0
    s._LAST_SUBMITTED_COUNTER = None


@pytest.fixture
def clock(monkeypatch):
    """Fake clock for the latch (``_clock``) and for the TOTP window (``time.time``)."""
    state = {"mono": 100.0, "now": NOW}
    monkeypatch.setattr(s, "_clock", lambda: state["mono"])
    monkeypatch.setattr(s, "time", SimpleNamespace(time=lambda: state["now"],
                                                   monotonic=time.monotonic))
    return state


@pytest.fixture
def harness(monkeypatch, clock):
    h = Harness()

    class _Browser:
        def new_context(self, **kwargs):
            return _Context()

        def close(self):
            h.closed += 1

    class _Context:
        def new_page(self):
            h.page = FakePage(h.next_urls, clock)
            h.pages.append(h.page)
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

    sync_api = types.ModuleType("patchright.sync_api")
    sync_api.sync_playwright = sync_playwright
    monkeypatch.setitem(sys.modules, "patchright", types.ModuleType("patchright"))
    monkeypatch.setitem(sys.modules, "patchright.sync_api", sync_api)
    monkeypatch.setattr(s, "get_credentials", lambda: ("user", "pw"))
    monkeypatch.setattr(s, "get_totp_seed", lambda: SEED)
    return h


def _read_url(page):
    return page.url


def test_1_login_without_code_page_runs_read(harness, clock, monkeypatch):
    monkeypatch.setattr(s, "get_totp_seed", lambda: pytest.fail("seed must not be read"))
    harness.next_urls = [HOME]
    assert s.run(_read_url) == HOME
    assert harness.launches == 1
    assert harness.closed == 1
    assert not [e for e in harness.page.events if e[0] == "press"]


def test_2_code_page_gets_the_code_once_then_read_runs(harness, clock):
    code = totp(SEED, NOW)
    harness.next_urls = [TFA, HOME]
    assert s.run(_read_url) == HOME
    fills = [i for i, e in enumerate(harness.page.events) if e[0] == "fill" and e[2] == code]
    assert len(fills) == 1
    clicks_after = [e for e in harness.page.events[fills[0]:] if e[0] == "click"]
    assert len(clicks_after) == 1
    assert clicks_after[0][1] == s.SUBMIT_BUTTON


def test_3_code_still_shown_after_submit_rejects_and_latches(harness, clock):
    harness.next_urls = [TFA, TFA]
    with pytest.raises(s.SecondFactorRejected):
        s.run(_read_url)
    assert s._BLOCKED_UNTIL == pytest.approx(100.0 + s.LATCH_S)
    assert harness.closed == 1


def test_4_next_run_is_latched_and_never_launches(harness, clock):
    harness.next_urls = [TFA, TFA]
    with pytest.raises(s.SecondFactorRejected):
        s.run(_read_url)
    launches = harness.launches
    with pytest.raises(s.LoginLatched):
        s.run(_read_url)
    assert harness.launches == launches


def test_5_run_proceeds_once_the_latch_period_has_passed(harness, clock):
    harness.next_urls = [LOGIN_ERR]
    with pytest.raises(s.LoginFailed):
        s.run(_read_url)
    clock["mono"] = 100.0 + s.LATCH_S - 1
    with pytest.raises(s.LoginLatched):
        s.run(_read_url)
    clock["mono"] = 100.0 + s.LATCH_S
    harness.next_urls = [HOME]
    assert s.run(_read_url) == HOME


def test_6_missing_seed_stops_with_second_factor_required_and_no_latch(harness, clock, monkeypatch):
    def no_seed():
        raise VaultError(f"vault_miss:{TOTP_KEY}")
    monkeypatch.setattr(s, "get_totp_seed", no_seed)
    harness.next_urls = [TFA]
    with pytest.raises(s.SecondFactorRequired):
        s.run(_read_url)
    assert s._BLOCKED_UNTIL == 0.0
    assert harness.closed == 1
    harness.next_urls = [HOME]
    assert s.run(_read_url) == HOME      # no latch: the next run is not blocked


def test_7_login_failed_also_latches(harness, clock):
    harness.next_urls = [LOGIN_ERR]
    with pytest.raises(s.LoginFailed):
        s.run(_read_url)
    assert s._BLOCKED_UNTIL == pytest.approx(100.0 + s.LATCH_S)


def _submitted(h):
    return [e[2] for page in h.pages for e in page.events if e[0] == "fill" and e[2].isdigit()]


def test_8_seed_and_code_never_reach_an_exception_or_a_return(harness, clock):
    harness.next_urls = [TFA, HOME]
    result = s.run(_read_url)
    assert SEED not in repr(result)

    s._BLOCKED_UNTIL = 0.0
    harness.next_urls = [TFA, TFA]
    with pytest.raises(s.SecondFactorRejected) as info:
        s.run(_read_url)
    err = info.value
    codes = _submitted(harness)
    assert len(codes) == 2
    for text in (str(err), repr(err), repr(err.args), repr(vars(err))):
        assert SEED not in text and all(c not in text for c in codes)
    with pytest.raises(s.LoginLatched) as latched:
        s.run(_read_url)
    assert SEED not in repr(latched.value) and all(c not in repr(latched.value) for c in codes)


def test_9_page_waits_first_when_the_window_is_nearly_over(harness, clock):
    late = 1_000_000_012.0                  # 22 s into the step; the login's 5 s of waits leave 3 s
    clock["now"] = late
    harness.next_urls = [TFA, HOME]
    assert s.run(_read_url) == HOME
    events = harness.page.events
    wait = events.index(("wait", 4000))
    # the code is computed after the wait, so it is for the step the wait reached (late + 5 + 4)
    fill = events.index(("fill", s.CODE_INPUT, totp(SEED, late + 9)))
    assert wait < fill


START = 1_000_000_000.0                      # 10 s into its step: two runs fit inside it


def _answer_fill(page):
    """The index and value of the code fill on one run's page."""
    i = next(i for i, e in enumerate(page.events) if e[0] == "fill" and e[1] == s.CODE_INPUT)
    return i, page.events[i][2]


def test_a_two_runs_in_one_step_second_waits_and_submits_a_different_code(harness, clock):
    clock["now"] = START
    harness.next_urls = [TFA, HOME]
    assert s.run(_read_url) == HOME
    first_code = _submitted(harness)[0]

    clock_before = clock["now"]              # run 1's own waits have moved the clock on
    harness.next_urls = [TFA, HOME]
    assert s.run(_read_url) == HOME
    answer_at = clock_before + 5             # run 2's login waits 2 s and 3 s before the answer
    assert s._counter(answer_at) == s._counter(START)    # premise: still the same step
    fill_index, second_code = _answer_fill(harness.page)
    assert ("wait", int((seconds_left(answer_at, s.TOTP_STEP_S) + 1) * 1000)) \
        in harness.page.events[:fill_index]
    assert second_code != first_code
    assert _submitted(harness) == [first_code, second_code]


def test_b_run_in_a_later_step_does_not_wait_for_the_guard(harness, clock):
    clock["now"] = START
    harness.next_urls = [TFA, HOME]
    assert s.run(_read_url) == HOME

    clock["now"] = START + s.TOTP_STEP_S     # the next step: the counter has advanced
    answer_at = clock["now"] + 5
    harness.next_urls = [TFA, HOME]
    assert s.run(_read_url) == HOME
    assert s._counter(answer_at) > s._counter(START)     # premise: a later step
    fill_index, code = _answer_fill(harness.page)
    waits_before_fill = [e[1] for e in harness.page.events[:fill_index] if e[0] == "wait"]
    assert all(ms <= 3000 for ms in waits_before_fill)   # login's own 2 s and 3 s only, no guard wait
    assert code == totp(SEED, answer_at)


def test_10_selftest_maps_the_new_error_types():
    assert t.selftest(runner=_raise(s.SecondFactorRejected())) == {
        "ok": False, "error_type": "second_factor_rejected"}
    assert t.selftest(runner=_raise(s.LoginLatched())) == {
        "ok": False, "error_type": "login_latched"}


def _raise(exc):
    def runner(read):
        raise exc
    return runner

