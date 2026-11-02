"""Pure parsing of saved ZoneEdit DNS panel HTML. Stdlib html.parser only: no browser, no network.

Every function accepts any string, including empty or garbage, and never raises on it.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser

_VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param",
         "source", "track", "wbr"}
_DNS_NAV = "DNS pagination"


class _Node:
    __slots__ = ("tag", "attrs", "children")

    def __init__(self, tag: str, attrs: dict[str, str]):
        self.tag = tag
        self.attrs = attrs
        self.children: list[_Node | str] = []


class _TreeBuilder(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = _Node("#root", {})
        self._stack = [self.root]

    def handle_starttag(self, tag, attrs):
        node = _Node(tag, {k: (v or "") for k, v in attrs})
        self._stack[-1].children.append(node)
        if tag not in _VOID:
            self._stack.append(node)

    def handle_endtag(self, tag):
        for i in range(len(self._stack) - 1, 0, -1):
            if self._stack[i].tag == tag:
                del self._stack[i:]
                return

    def handle_data(self, data):
        self._stack[-1].children.append(data)


def _parse(html: str) -> _Node:
    builder = _TreeBuilder()
    builder.feed(html or "")
    builder.close()
    return builder.root


def _iter(node: _Node):
    for child in node.children:
        if isinstance(child, _Node):
            yield child
            yield from _iter(child)


def _classes(node: _Node) -> list[str]:
    return node.attrs.get("class", "").split()


def _has_class(node: _Node, name: str) -> bool:
    return name in _classes(node)


def _text(node: _Node) -> str:
    parts: list[str] = []

    def walk(n: _Node) -> None:
        for child in n.children:
            if isinstance(child, str):
                parts.append(child)
            else:
                walk(child)

    walk(node)
    return " ".join(" ".join(parts).replace("\xa0", " ").split())


def _is_rdata(node: _Node) -> bool:
    return node.tag == "span" and _has_class(node, "rdata")


def _content(cell: _Node | None, rdata: _Node | None) -> str:
    """The full record value: the content cell's title when set (the span shows a truncated
    value for long records), else the span text."""
    if cell is not None and cell.attrs.get("title", "").strip():
        return cell.attrs["title"].strip()
    return _text(rdata) if rdata is not None else ""


def _dns_navs(root: _Node) -> list[_Node]:
    return [n for n in _iter(root) if n.tag == "nav" and n.attrs.get("aria-label") == _DNS_NAV]


_PENDING_LABELS = ("Queued record", "Queued record deletion", "Record currently revoked")


def _pending(row: _Node) -> bool:
    """True when a queued, queued-for-deletion or revoked icon is shown (no display: none)."""
    for node in _iter(row):
        if node.attrs.get("aria-label") in _PENDING_LABELS:
            if "display:none" not in node.attrs.get("style", "").replace(" ", ""):
                return True
    return False


def parse_records(html: str) -> list[dict]:
    """One dict per record row (``div.item-wrapped``): type, host, content, ttl, hash, pending.

    The hidden edit form is a ``form`` child of each row, not a cell, so it never yields a field.
    """
    records: list[dict] = []
    for row in _iter(_parse(html)):
        if row.tag != "div" or not _has_class(row, "item-wrapped"):
            continue
        cells = [c for c in row.children if isinstance(c, _Node) and c.tag == "div"]
        rdata = None
        content_cell = None
        for cell in cells:
            found = next((s for s in _iter(cell) if _is_rdata(s)), None)
            if found is not None:
                rdata, content_cell = found, cell
                break
        type_cell = next((c for c in cells if _has_class(c, "col-md-2")), None)
        host_cell = next((c for c in cells
                          if _has_class(c, "col-md-4") and c is not content_cell), None)
        ttl_cell = next((c for c in cells
                         if _has_class(c, "col-md-1") and _has_class(c, "item")
                         and not _has_class(c, "mt-3")), None)
        records.append({
            "type": _text(type_cell) if type_cell else "",
            "host": _text(host_cell) if host_cell else "",
            "content": _content(content_cell, rdata),
            "ttl": _text(ttl_cell) if ttl_cell else "",
            "hash": row.attrs.get("data-hash", ""),
            "pending": _pending(row),
        })
    return records


def parse_total(html: str) -> int | None:
    """The N in ``Total: N`` inside the DNS pagination nav; None when absent."""
    for nav in _dns_navs(_parse(html)):
        match = re.search(r"Total:\s*(\d+)", _text(nav))
        if match:
            return int(match.group(1))
    return None


def parse_pages(html: str) -> int:
    """The highest numeric page-item label in the DNS pagination list; 1 when there is none."""
    best = 1
    for nav in _dns_navs(_parse(html)):
        for item in _iter(nav):
            if item.tag == "li" and _has_class(item, "page-item"):
                label = _text(item)
                if label.isdigit():
                    best = max(best, int(label))
    return best
