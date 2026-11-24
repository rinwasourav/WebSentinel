"""HTML anchor extraction without executing page content."""

from __future__ import annotations

from html.parser import HTMLParser


class _AnchorParser(HTMLParser):
    def __init__(self, maximum: int) -> None:
        super().__init__(convert_charrefs=True)
        self.maximum = maximum
        self.links: list[str] = []
        self.truncated = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() not in {"a", "area"}:
            return
        href = next((value for name, value in attrs if name.lower() == "href"), None)
        if href is None:
            return
        if len(self.links) >= self.maximum:
            self.truncated = True
            return
        self.links.append(href)


def extract_links(document: str, *, maximum: int = 250) -> tuple[list[str], bool]:
    """Extract a bounded list of anchor URLs; scripts and forms are never run."""
    parser = _AnchorParser(maximum)
    parser.feed(document)
    parser.close()
    return parser.links, parser.truncated
