"""The real headless Chrome for the tests that drive synthetic pages offline: ``test_clickpaths.py`` and
``test_schema_dom.py``. ``chrome`` is one browser per test module; ``make_page`` gives each test its own
offline context whose every request is aborted until the test routes its own pages.
"""
import sys

import pytest

import zoneedit_session as s

DOMAIN_NAMES = ["example.com", "example.net", "example.org"]


def list_page(names=DOMAIN_NAMES, shown=None, total=None, extra=""):
    """The domain list page: the count text, then two links per name (the manage and the DNS link).
    ``shown``/``total`` default to the number of names. ``extra`` is raw HTML appended to the body."""
    shown = len(names) if shown is None else shown
    total = len(names) if total is None else total
    rows = "".join(
        f'<tr><td>{name}</td><td>'
        f'<a href="https://cp.zoneedit.com/manage/domains/?LOGIN={name}">Manage</a> '
        f'<a href="https://cp.zoneedit.com/manage/domains/dns/index.php?LOGIN={name}">DNS</a>'
        f'</td></tr>' for name in names)
    return (f'<!doctype html><html><head><meta charset="utf-8"><title>Domains</title></head><body>'
            f'<p>Showing {shown} out of {total} total</p>'
            f'<table>{rows}</table>{extra}</body></html>')


@pytest.fixture(scope="module")
def chrome():
    # conftest.py installs a tripwire for patchright; this module needs the real one. Every
    # patchright* entry must go, or the real package imports against the tripwire's stub parent.
    # One browser serves the whole module, and each test gets its own offline context.
    with pytest.MonkeyPatch.context() as patch:
        for name in [k for k in list(sys.modules) if k == "patchright" or k.startswith("patchright.")]:
            patch.delitem(sys.modules, name, raising=False)
        from patchright.sync_api import sync_playwright

        playwright = sync_playwright().start()
        try:
            browser = playwright.chromium.launch(channel="chrome", headless=True, args=s.chrome_args())
        except Exception as ex:
            playwright.stop()
            pytest.skip(f"Chrome cannot be launched here ({type(ex).__name__})")
        try:
            yield browser
        finally:
            browser.close()
            playwright.stop()


@pytest.fixture
def make_page(chrome):
    contexts = []

    def make():
        context = chrome.new_context(user_agent=s.USER_AGENT, viewport=s.VIEWPORT, offline=True,
                                     service_workers="block")
        context.route("**/*", lambda route: route.abort())
        contexts.append(context)
        return context.new_page()

    yield make
    for context in contexts:
        context.close()
