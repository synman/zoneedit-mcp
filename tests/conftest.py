"""No test may launch a real browser. A launch means a live login with the panel's real credentials,
and a repeated failed login can lock the account.

``patchright.sync_api`` is replaced for every test by a tripwire. ``zoneedit_session.run`` turns any
exception into ``SessionError``, so the trip is also recorded and asserted at teardown: a swallowed
failure still fails the test. A test that needs a browser double installs its own with
``monkeypatch.setitem(sys.modules, ...)``, which replaces the tripwire for that test only.
"""
from __future__ import annotations

import sys
import types

import pytest


@pytest.fixture(autouse=True)
def no_real_browser(monkeypatch):
    tripped: list[str] = []

    def sync_playwright():
        tripped.append("sync_playwright")
        raise AssertionError("a test reached a real browser launch; install a fake in sys.modules")

    api = types.ModuleType("patchright.sync_api")
    api.sync_playwright = sync_playwright
    package = types.ModuleType("patchright")
    package.sync_api = api
    monkeypatch.setitem(sys.modules, "patchright", package)
    monkeypatch.setitem(sys.modules, "patchright.sync_api", api)
    yield tripped
    assert not tripped, "a test launched a real browser and the failure was swallowed"
