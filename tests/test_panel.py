import pytest
from pathlib import Path

import zoneedit_panel as p

FIXTURES = Path(__file__).parent / "fixtures"
HTML = (FIXTURES / "dns_index.html").read_text(encoding="utf-8")

EXPECTED_ORDER = [
    ("CAA", "@"),
    ("CNAME", "autodiscover"),
    ("CNAME", "app-a"),
    ("CNAME", "app-b"),
    ("CNAME", "email"),
    ("CNAME", "home"),
    ("CNAME", "mail"),
    ("CNAME", "meet"),
    ("CNAME", "meet-rtc"),
    ("CNAME", "meet-turn"),
]


def test_ten_records_in_panel_order():
    records = p.parse_records(HTML)
    assert [(r["type"], r["host"]) for r in records] == EXPECTED_ORDER


def test_first_record_exact():
    assert p.parse_records(HTML)[0] == {
        "type": "CAA",
        "host": "@",
        "content": "0 issue letsencrypt.org",
        "ttl": "[DEF] 2 hours",
        "hash": "65e3f174cd4ca4152c4074c18d628ec7",
            "pending": False,
    }


def test_contents_match_fixture():
    contents = {r["host"]: r["content"] for r in p.parse_records(HTML)}
    assert contents["autodiscover"] == "autodiscover.outlook.com."
    assert contents["app-a"] == "target.example.net."
    assert contents["app-b"] == "target.example.net."
    assert contents["email"] == "email.secureserver.net."
    assert contents["home"] == "target.example.net."
    assert contents["meet"] == "target.example.net."
    assert contents["meet-rtc"] == "target.example.net."
    assert contents["meet-turn"] == "target.example.net."
    assert contents["mail"] == "example-com.mail.protection.outlook.com."


def test_mail_content_is_full_value_not_panel_truncation():
    # The span.rdata text is truncated by the panel ("...outlook.co..."); the content cell's
    # title holds the full value that write tools must match exactly.
    mail = next(r for r in p.parse_records(HTML) if r["host"] == "mail")
    assert mail["content"] == "example-com.mail.protection.outlook.com."
    assert mail["content"] != "example-com.mail.protection.outlook.co..."


def test_every_ttl_is_panel_default():
    assert {r["ttl"] for r in p.parse_records(HTML)} == {"[DEF] 2 hours"}


def test_every_record_has_fields_and_hidden_form_yields_nothing():
    records = p.parse_records(HTML)
    assert len(records) == 10
    for r in records:
        assert set(r) == {"type", "host", "content", "ttl", "hash", "pending"}
        assert r["type"] and r["host"] and r["content"] and r["hash"]
        assert "formEditRecord" not in r["content"]


def test_total_and_pages_from_fixture():
    assert p.parse_total(HTML) == 28
    assert p.parse_pages(HTML) == 3


def test_zero_total_outside_pagination_is_not_the_total():
    assert p.parse_total("<div>Total: 0</div>") is None
    assert p.parse_total('<nav aria-label="DNS pagination"><div>Total: 0</div></nav>') == 0


def test_garbage_and_empty_html_never_raise():
    assert p.parse_records("") == []
    assert p.parse_records("<<<>>> &&& </div></span>") == []
    assert p.parse_total("") is None
    assert p.parse_pages("") == 1


def test_base_fixture_has_no_pending_rows():
    assert [r["pending"] for r in p.parse_records(HTML)] == [False] * 10


@pytest.mark.parametrize("label", [
    "Queued record",
    "Queued record deletion",
    "Record currently revoked",
])
def test_one_shown_icon_marks_only_its_row_pending(label):
    hidden = f'style="display: none;" aria-label="{label}"'
    assert HTML.count(hidden) >= 1
    shown = HTML.replace(hidden, f'aria-label="{label}"', 1)
    assert shown != HTML
    assert [r["pending"] for r in p.parse_records(shown)] == [True] + [False] * 9
