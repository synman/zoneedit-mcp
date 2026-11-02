"""The suite-wide tripwire in conftest.py: a real browser launch is recorded, not performed."""
from __future__ import annotations

import sys

import pytest

import zoneedit_session


def test_run_reaches_the_tripwire_and_never_a_browser(no_real_browser, monkeypatch):
    monkeypatch.setattr(zoneedit_session, "get_credentials", lambda: ("user", "secret"))
    api = sys.modules["patchright.sync_api"]
    assert api.sync_playwright.__module__ == "conftest"
    with pytest.raises(zoneedit_session.SessionError) as raised:
        zoneedit_session.run(lambda page: None)
    assert raised.value.error_type == "AssertionError"
    assert no_real_browser == ["sync_playwright"]
    no_real_browser.clear()
