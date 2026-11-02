"""Session hardening: the run deadline and watchdog, RunBusy, the confirmed-write deadline, the user
agent from the installed Chrome, and the real kill path.

Watchdog tests replace the worker body through the seam ``zoneedit_session._run_body`` and the kill
through ``_kill_descendants``; every ``run()`` call goes through ``_run``, which bounds it, so a
regression that stops run() from returning fails a test in seconds instead of hanging the suite.
Kill-path tests spawn real child processes and kill only those."""
from __future__ import annotations

import os
import random
import signal
import subprocess
import sys
import threading
import time
import types
from types import SimpleNamespace

import pytest

import zoneedit_session as s
import zoneedit_writes as w

CANARY_TEXT = "fuzz-canary-7e41-not-a-real-credential"
ALLOWED = (s.SessionError, s.SecondFactorRequired, s.LoginFailed, s.SecondFactorRejected,
           s.LoginLatched)
FUZZ_SEEDS = range(60)
FAST = {"RUN_DEADLINE_S": 0.05, "LOCK_WAIT_S": 0.1, "KILL_GRACE_S": 0.02}


class Plan:
    """One run's fake behaviour. ``kind``: return (waits ``dur``, killable), raise (killable wait,
    then ``exc()``), hang (blocks until killed), ignore (waits ``dur`` and ignores the kill)."""

    def __init__(self, token, kind="return", dur=0.0, exc=None):
        self.token = token
        self.kind = kind
        self.dur = dur
        self.exc = exc


KILL_ERRORS = [
    lambda: OSError("ps failed"),
    lambda: subprocess.TimeoutExpired(["ps", "-axo", "pid=,ppid="], 5),
    lambda: RuntimeError("unexpected while parsing the process table"),
]


class Seam:
    """Replaces ``_run_body`` and ``_kill_descendants``; counts kills and checks one body at a time.

    With ``rng`` set, about half the kill calls raise after they have woken the waiters, so the body
    is never leaked: the failure is the kill step's, not a body that keeps running."""

    def __init__(self, rng: random.Random | None = None):
        self.lock = threading.Lock()
        self.rng = rng
        self.kills = 0
        self.waiters: list[threading.Event] = []
        self.active = 0
        self.max_active = 0
        self.started: set[str] = set()
        self.finished: set[str] = set()

    def kill(self) -> int:
        with self.lock:
            self.kills += 1
            for event in self.waiters:
                event.set()
        if self.rng is not None and self.rng.random() < 0.5:
            raise self.rng.choice(KILL_ERRORS)()
        return 0

    def body(self, read):
        with self.lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
            self.started.add(read.token)
            event = threading.Event()
            self.waiters.append(event)
        try:
            if read.kind == "hang":
                event.wait()
            elif read.kind == "ignore":
                threading.Event().wait(read.dur)
            else:
                event.wait(read.dur)
            if read.kind == "raise":
                raise read.exc()
            return read.token
        finally:
            with self.lock:
                self.active -= 1
                self.waiters.remove(event)
                self.finished.add(read.token)


@pytest.fixture(autouse=True)
def _free_stuck_lock():
    """Under a regression that stops run() from returning, a stuck run keeps _LOCK. Free it after each
    test so the later tests (and tests in other files) fail fast instead of waiting out LOCK_WAIT_S.
    Under correct code no run is left holding the lock, so this never changes a passing result."""
    yield
    if s._LOCK.locked():
        s._LOCK.release()


@pytest.fixture
def seam(monkeypatch):
    for name, value in FAST.items():
        monkeypatch.setattr(s, name, value)
    monkeypatch.setattr(s, "_LEAKED_WORKERS", 0)
    monkeypatch.setattr(s, "_BLOCKED_UNTIL", 0.0)
    fake = Seam()
    monkeypatch.setattr(s, "_run_body", fake.body)
    monkeypatch.setattr(s, "_kill_descendants", fake.kill)
    return fake


def _run(read, bound=None):
    """``run(read)`` on a helper thread. Fails with a message if run() has not returned by ``bound``
    seconds (default: the patched constants' sum plus 1 s), so a regression cannot stall the suite."""
    if bound is None:
        bound = s.LOCK_WAIT_S + s.RUN_DEADLINE_S + s.KILL_GRACE_S + 1.0
    box: dict = {}

    def target():
        try:
            box["r"] = ("ok", s.run(read))
        except BaseException as ex:
            box["r"] = ("err", ex)

    helper = threading.Thread(target=target, daemon=True, name="run-caller")
    helper.start()
    helper.join(bound)
    if helper.is_alive():
        pytest.fail(f"run() did not return within {bound:.2f}s: a watchdog timeout is missing "
                    "or not honoured", pytrace=False)
    kind, value = box["r"]
    if kind == "err":
        raise value
    return value


# --- Watchdog unit tests -----------------------------------------------------------------------

def test_body_finishing_in_time_returns_its_value_and_never_kills(seam):
    assert _run(Plan("t1", "return", 0.01)) == "t1"
    assert seam.kills == 0


def test_hung_body_is_killed_once_and_raises_run_deadline(seam):
    with pytest.raises(s.RunDeadlineExceeded) as info:
        _run(Plan("t2", "hang"))
    assert seam.kills == 1
    assert info.value.error_type == "RunDeadlineExceeded"
    assert info.value.url == ""
    assert str(info.value) == "RunDeadlineExceeded"
    assert s._LOCK.acquire(blocking=False)      # the lock is released after the deadline
    s._LOCK.release()


def test_second_caller_gets_run_busy_and_never_starts_a_body(seam, monkeypatch):
    monkeypatch.setattr(s, "RUN_DEADLINE_S", 1.0)    # the holder outlives LOCK_WAIT_S, not the deadline
    holder = threading.Thread(target=lambda: s.run(Plan("holder", "return", 0.3)), daemon=True)
    holder.start()
    until = time.monotonic() + 2.0
    while "holder" not in seam.started and time.monotonic() < until:
        time.sleep(0.005)
    assert "holder" in seam.started, "the holder run never started"
    with pytest.raises(s.RunBusy) as info:
        _run(Plan("second", "return", 0.0))
    assert info.value.error_type == "RunBusy"
    assert info.value.url == ""
    assert "second" not in seam.started
    holder.join(5)
    assert not holder.is_alive()
    assert seam.kills == 0


def test_late_result_is_discarded_and_never_returned_to_a_later_call(seam, monkeypatch):
    monkeypatch.setattr(s, "KILL_GRACE_S", 0.2)     # the body finishes inside this grace, after the deadline
    with pytest.raises(s.RunDeadlineExceeded):
        _run(Plan("late", "ignore", 0.12))
    assert seam.kills == 1
    assert s._LEAKED_WORKERS == 0
    assert _run(Plan("fresh", "return", 0.0)) == "fresh"


def test_worker_still_alive_after_grace_is_leaked_and_lock_released(seam):
    with pytest.raises(s.RunDeadlineExceeded):
        _run(Plan("stuck", "ignore", 0.4))         # ignores the kill; alive after the grace
    assert s._LEAKED_WORKERS == 1
    assert _run(Plan("after", "return", 0.0)) == "after"


def test_run_deadline_never_sets_the_credential_latch(seam):
    with pytest.raises(s.RunDeadlineExceeded):
        _run(Plan("d", "hang"))
    assert s._BLOCKED_UNTIL == 0.0
    assert _run(Plan("next", "return", 0.0)) == "next"


KILL_FAILURE_CASES = [
    pytest.param(lambda: OSError("ps failed"), id="oserror"),
    pytest.param(lambda: subprocess.TimeoutExpired(["ps", "-axo", "pid=,ppid="], 5), id="timeout"),
    pytest.param(lambda: RuntimeError("unexpected"), id="any-exception"),
]


@pytest.mark.parametrize("make_error", KILL_FAILURE_CASES)
def test_kill_failure_still_ends_in_deadline_after_the_grace(seam, monkeypatch, make_error):
    monkeypatch.setattr(s, "KILL_GRACE_S", 0.2)     # the body finishes inside this grace, after the deadline
    monkeypatch.setattr(s, "_KILL_FAILURES", 0)

    def failing_kill():
        raise make_error()

    monkeypatch.setattr(s, "_kill_descendants", failing_kill)
    with pytest.raises(s.RunDeadlineExceeded):
        _run(Plan("k", "ignore", 0.12))
    assert "k" in seam.finished                     # the grace join waited for the worker
    assert s._KILL_FAILURES == 1
    assert s._LOCK.acquire(blocking=False)          # the lock is free afterwards
    s._LOCK.release()


@pytest.mark.parametrize("make_error", KILL_FAILURE_CASES)
def test_confirmed_write_maps_to_unknown_when_the_kill_fails(monkeypatch, make_error):
    for name, value in FAST.items():
        monkeypatch.setattr(s, name, value)
    monkeypatch.setattr(s, "KILL_GRACE_S", 0.2)
    monkeypatch.setattr(s, "_BLOCKED_UNTIL", 0.0)
    finished = threading.Event()

    def hung_body(read):                             # ignores the kill; finishes inside the grace
        threading.Event().wait(0.12)
        finished.set()
        return "done"

    def failing_kill():
        raise make_error()

    monkeypatch.setattr(s, "_run_body", hung_body)
    monkeypatch.setattr(s, "_kill_descendants", failing_kill)
    result = w.write_record(s.run, "add", type_="TXT", host="probe", content="v", confirmed=True)
    assert result == {"ok": False, "confirmed": True, "outcome": "unknown",
                      "message": w.UNKNOWN_MESSAGE, "error_type": "RunDeadlineExceeded",
                      "action": "add", "domain": None}
    assert finished.is_set()
    assert s._LOCK.acquire(blocking=False)
    s._LOCK.release()


def test_worker_exception_keeps_its_identity(seam):
    err = s.SecondFactorRejected()
    with pytest.raises(s.SecondFactorRejected) as info:
        _run(Plan("x", "raise", 0.0, exc=lambda: err))
    assert info.value is err
    assert seam.kills == 0


# --- Confirmed-write deadline ------------------------------------------------------------------

def _raising_deadline(read):
    raise s.RunDeadlineExceeded()


def test_confirmed_write_on_deadline_is_outcome_unknown():
    result = w.write_record(_raising_deadline, "add", type_="TXT", host="probe",
                            content="v", confirmed=True)
    assert result == {"ok": False, "confirmed": True, "outcome": "unknown",
                      "message": w.UNKNOWN_MESSAGE, "error_type": "RunDeadlineExceeded",
                      "action": "add", "domain": None}


def test_unconfirmed_write_on_deadline_propagates():
    with pytest.raises(s.RunDeadlineExceeded):
        w.write_record(_raising_deadline, "add", type_="TXT", host="probe", content="v",
                       confirmed=False)


# --- User agent --------------------------------------------------------------------------------

MAC_UA = s.USER_AGENT


@pytest.mark.parametrize("version, expected", [
    ("156.0.8078.79", MAC_UA),
    ("157.0.1.2", MAC_UA.replace("Chrome/156.0.0.0", "Chrome/157.0.0.0")),
    (None, MAC_UA),
    ("", MAC_UA),
    ("garbage", MAC_UA),
    ("HeadlessChrome/156.0.1.2", MAC_UA),
])
def test_user_agent_follows_the_installed_chrome_major(version, expected):
    ua = s.user_agent_for(SimpleNamespace(version=version))
    assert ua == expected
    assert "HeadlessChrome" not in ua


def test_user_agent_without_a_version_attribute_is_the_fallback():
    assert s.user_agent_for(SimpleNamespace()) == MAC_UA


def test_run_passes_the_chrome_user_agent_and_sets_timeouts(monkeypatch):
    seen: dict = {}

    class _Context:
        def __init__(self):
            self.timeouts = []

        def set_default_timeout(self, ms):
            self.timeouts.append(ms)

        def set_default_navigation_timeout(self, ms):
            self.timeouts.append(ms)

        def new_page(self):
            return object()

    class _Browser:
        version = "157.0.1.2"

        def new_context(self, **kwargs):
            seen["kwargs"] = kwargs
            seen["context"] = _Context()
            return seen["context"]

        def close(self):
            seen["closed"] = True

    class _Chromium:
        def launch(self, **kwargs):
            return _Browser()

    class _CM:
        def __enter__(self):
            return SimpleNamespace(chromium=_Chromium())

        def __exit__(self, *exc):
            return False

    sync_api = types.ModuleType("patchright.sync_api")
    sync_api.sync_playwright = lambda: _CM()
    monkeypatch.setitem(sys.modules, "patchright", types.ModuleType("patchright"))
    monkeypatch.setitem(sys.modules, "patchright.sync_api", sync_api)
    monkeypatch.setattr(s, "get_credentials", lambda: ("u", "p"))
    monkeypatch.setattr(s, "login", lambda page, user, password: None)

    assert _run(lambda page: "ok", bound=10) == "ok"
    assert "HeadlessChrome" not in seen["kwargs"]["user_agent"]
    assert "Chrome/157.0.0.0" in seen["kwargs"]["user_agent"]
    assert seen["kwargs"]["viewport"] == s.VIEWPORT
    assert seen["context"].timeouts == [30000, 30000]
    assert seen["closed"] is True


# --- Fuzz: invariants I1 to I6 -----------------------------------------------------------------

FUZZ_EXC = [
    lambda: s.SecondFactorRequired(),
    lambda: s.LoginFailed(),
    lambda: s.SecondFactorRejected(),
    lambda: s.LoginLatched(),
    lambda: s.SessionError("BrowserError", "https://cp.zoneedit.com/manage/x"),
]


def _fuzz_plans(seed: int, rng: random.Random, count: int) -> list[Plan]:
    plans = []
    for i in range(count):
        token = f"s{seed}-c{i}"
        roll = rng.random()
        dur = rng.uniform(0.0, 0.1)
        if roll < 0.4:
            plans.append(Plan(token, "return", dur))
        elif roll < 0.6:
            plans.append(Plan(token, "raise", dur, exc=rng.choice(FUZZ_EXC)))
        else:
            plans.append(Plan(token, "hang"))
    return plans


def test_fuzz_watchdog_invariants(monkeypatch):
    for name, value in FAST.items():
        monkeypatch.setattr(s, name, value)
    monkeypatch.setattr(s, "_LEAKED_WORKERS", 0)
    monkeypatch.setattr(s, "_BLOCKED_UNTIL", 0.0)
    bound = s.LOCK_WAIT_S + s.RUN_DEADLINE_S + s.KILL_GRACE_S + 1.0
    counts_seen: set[int] = set()

    for seed in FUZZ_SEEDS:
        rng = random.Random(seed)
        seam = Seam(rng)
        monkeypatch.setattr(s, "_run_body", seam.body)
        monkeypatch.setattr(s, "_kill_descendants", seam.kill)
        count = rng.randint(1, 3)
        counts_seen.add(count)
        plans = _fuzz_plans(seed, rng, count)
        results: list = [None] * count

        def caller(i):
            started = time.monotonic()
            try:
                outcome = ("ok", s.run(plans[i]))
            except BaseException as ex:
                outcome = ("err", ex)
            results[i] = (outcome, time.monotonic() - started)

        threads = [threading.Thread(target=caller, args=(i,), daemon=True) for i in range(count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(bound + 1)
            assert not thread.is_alive(), f"seed {seed}: a caller never returned"

        deadline_tokens: set[str] = set()
        ok_values: list[str] = []
        deadlines = 0
        for plan, (outcome, elapsed) in zip(plans, results):
            assert elapsed <= bound, f"seed {seed}: run took {elapsed:.2f}s"                 # I2
            kind, value = outcome
            if kind == "ok":
                assert value == plan.token, f"seed {seed}: wrong result"                    # I4
                ok_values.append(value)
                continue
            assert isinstance(value, (s.RunDeadlineExceeded, s.RunBusy) + ALLOWED), \
                f"seed {seed}: disallowed {type(value).__name__}"                           # I3
            assert CANARY_TEXT not in str(value) and CANARY_TEXT not in repr(value)
            if isinstance(value, s.RunBusy):
                assert plan.token not in seam.started, f"seed {seed}: busy caller ran a body"
            if isinstance(value, s.RunDeadlineExceeded):
                deadlines += 1
                deadline_tokens.add(plan.token)

        assert not (set(ok_values) & deadline_tokens), f"seed {seed}: late result returned"  # I4
        assert seam.max_active <= 1, f"seed {seed}: two worker bodies ran at once"           # I1
        assert seam.kills <= deadlines, f"seed {seed}: kill attempted more than once per deadline"  # I6
        assert s._LOCK.acquire(blocking=False), f"seed {seed}: lock left held"              # I5
        s._LOCK.release()

    assert counts_seen == {1, 2, 3}, f"caller counts exercised: {sorted(counts_seen)}"


# --- Real kill path ----------------------------------------------------------------------------

def _dead(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    return False


def test_real_kill_signals_a_real_child():
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        signalled = s._kill_descendants()
        assert signalled >= 1
        assert child.wait(timeout=3) == -signal.SIGKILL    # dead within 3 s, killed by SIGKILL
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()


def test_real_kill_signals_a_real_grandchild_too():
    script = ("import subprocess, sys, time\n"
              "g = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
              "print(g.pid, flush=True)\n"
              "time.sleep(60)\n")
    child = subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE, text=True)
    grandchild_pid: list[int] = []

    def read_pid():
        grandchild_pid.append(int(child.stdout.readline()))

    reader = threading.Thread(target=read_pid, daemon=True)
    reader.start()
    reader.join(5)
    assert grandchild_pid, "the child never reported its grandchild pid"
    try:
        signalled = s._kill_descendants()
        assert signalled >= 2
        assert child.wait(timeout=3) == -signal.SIGKILL
        until = time.monotonic() + 3
        while not _dead(grandchild_pid[0]) and time.monotonic() < until:
            time.sleep(0.05)
        assert _dead(grandchild_pid[0]), "the grandchild survived the kill"
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
        if not _dead(grandchild_pid[0]):
            os.kill(grandchild_pid[0], signal.SIGKILL)


def test_kill_signals_only_descendants_synthetic_tree(monkeypatch):
    me = os.getpid()
    tree = {1: 0, me: 1, 100: me, 101: me, 200: 100, 201: 200, 300: 999, 301: 300, 999: 1}
    monkeypatch.setattr(s, "_process_parents", lambda: dict(tree))
    sent: list[tuple[int, int]] = []
    monkeypatch.setattr(s.os, "kill", lambda pid, sig: sent.append((pid, sig)))
    assert s._kill_descendants() == 4
    assert sorted(pid for pid, _ in sent) == [100, 101, 200, 201]
    assert all(sig == signal.SIGKILL for _, sig in sent)
    assert me not in {pid for pid, _ in sent}


def test_kill_counts_only_pids_it_actually_signalled(monkeypatch):
    me = os.getpid()
    monkeypatch.setattr(s, "_process_parents", lambda: {100: me, 101: me, 102: me, 103: me})

    def fake_kill(pid, sig):
        if pid == 101:
            raise ProcessLookupError()
        if pid == 102:
            raise PermissionError()

    monkeypatch.setattr(s.os, "kill", fake_kill)
    assert s._kill_descendants() == 2


@pytest.mark.parametrize("text, parent", [
    ("1234 (we ird) name) S 77 1 1 0 -1", 77),
    ("5 (sh) S 1 5 5 0 -1", 1),
    ("9 ((x)) R 42 9 9 0 -1", 42),
])
def test_parent_from_stat_handles_spaces_and_parentheses_in_the_name(text, parent):
    assert s._parent_from_stat(text) == parent


CANNED_PS = "  1     0\n  77     1\n\n  abc  def\n  12\n 9 2 extra\n  100   77\n"


def test_ps_fallback_parses_canned_output_and_skips_blank_and_malformed_lines():
    assert s._parse_ps(CANNED_PS) == {1: 0, 77: 1, 100: 77}


def test_process_parents_uses_ps_when_proc_is_absent(monkeypatch, tmp_path):
    monkeypatch.setattr(s, "_PROC", str(tmp_path / "no-proc"))
    seen: list = []

    def fake_run(argv, **kwargs):
        seen.append(argv)
        return SimpleNamespace(returncode=0, stdout=CANNED_PS)

    monkeypatch.setattr(s.subprocess, "run", fake_run)
    assert s._process_parents() == {1: 0, 77: 1, 100: 77}
    assert seen and seen[0][0] == "ps"


def test_process_parents_reads_proc_files_when_present(monkeypatch, tmp_path):
    (tmp_path / "self").mkdir()
    (tmp_path / "self" / "stat").write_text("1 (self) S 0 1 1 0 -1\n")
    for pid, parent in ((10, 1), (11, 10)):
        (tmp_path / str(pid)).mkdir()
        (tmp_path / str(pid) / "stat").write_text(f"{pid} (we ird) name) S {parent} 1 1 0 -1\n")
    (tmp_path / "junk").mkdir()
    monkeypatch.setattr(s, "_PROC", str(tmp_path))

    def no_ps(argv, **kwargs):
        raise AssertionError("ps must not run when /proc is readable")

    monkeypatch.setattr(s.subprocess, "run", no_ps)
    assert s._process_parents() == {10: 1, 11: 10}      # "self" and "junk" are not pids
