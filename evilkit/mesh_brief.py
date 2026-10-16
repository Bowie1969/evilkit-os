"""Read an engagement brief as complete human-readable text for Kimi sessions."""

from __future__ import annotations

import hashlib
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit


class BriefError(ValueError):
    pass


class _ReadableHTML(HTMLParser):
    _BLOCKS = frozenset({"address", "article", "aside", "blockquote", "br", "dd", "div", "dl", "dt", "footer", "h1", "h2", "h3", "h4", "h5", "h6", "header", "li", "main", "nav", "ol", "p", "section", "table", "td", "th", "tr", "ul"})
    _SKIP = frozenset({"script", "style", "svg", "noscript", "template"})

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.skipping = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self._SKIP:
            self.skipping += 1
        elif not self.skipping and tag in self._BLOCKS:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SKIP:
            self.skipping = max(0, self.skipping - 1)
        elif not self.skipping and tag in self._BLOCKS:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self.skipping:
            self.parts.append(data)

    def text(self) -> str:
        lines = (" ".join(line.split()) for line in "".join(self.parts).splitlines())
        return "\n".join(line for line in lines if line)


def _follow_pointer(path: Path) -> Path:
    raw = path.read_text(encoding="utf-8", errors="replace").strip()
    if path.suffix.lower() != ".txt" or not raw.startswith("file://") or "\n" in raw:
        return path
    parsed = urlsplit(raw)
    if parsed.scheme != "file" or parsed.netloc not in ("", "localhost") or parsed.query or parsed.fragment:
        raise BriefError("brief pointer must be a local file URL")
    return Path(unquote(parsed.path))


def read_brief(path: Path) -> tuple[str, str]:
    """Return (full readable body, SHA-256); reject instead of truncating."""
    try:
        source = _follow_pointer(path.expanduser().resolve())
        raw = source.read_bytes()
    except OSError as exc:
        raise BriefError(f"could not read engagement brief: {exc}") from exc
    if len(raw) > 8_000_000:
        raise BriefError("engagement brief is too large to load intact")
    if b"MIME-Version:" in raw[:1000] and b"multipart/related" in raw[:2000]:
        message = BytesParser(policy=policy.default).parsebytes(raw)
        parts = [part for part in message.walk() if part.get_content_type() == "text/html"]
        if not parts:
            raise BriefError("MHTML brief contains no HTML page")
        html = parts[0].get_payload(decode=True).decode("utf-8", "replace")
        parser = _ReadableHTML()
        parser.feed(html)
        text = parser.text()
    elif source.suffix.lower() in (".html", ".htm"):
        parser = _ReadableHTML()
        parser.feed(raw.decode("utf-8", "replace"))
        text = parser.text()
    else:
        text = raw.decode("utf-8", "replace").strip()
    if not text:
        raise BriefError("engagement brief is empty")
    if len(text) > 100_000:
        raise BriefError("readable engagement brief exceeds the 100,000-character prompt limit")
    return text, hashlib.sha256(text.encode("utf-8")).hexdigest()
