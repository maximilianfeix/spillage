"""Rewrites README.md for PyPI: `python .github/pypi_readme.py v0.9.1`, in the release workflow.

The README is written for GitHub, which resolves `docs/banner-dark.svg` and `LICENSE` against the
repository. PyPI shows the same text without the repository behind it, so every relative image is
broken there and every relative link leads nowhere. This points them at the tagged commit, which
also keeps an old release's page showing that release's screenshots.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = "maximilianfeix/spillage"
_ABSOLUTE = re.compile(r"^(?:[a-z][a-z0-9+.-]*:|#|//)", re.IGNORECASE)  # https:, mailto:, #anchor
_PICTURE = re.compile(r"<picture>.*?(<img\b[^>]*>).*?</picture>", re.S)
_SRC = re.compile(r"""(<img\b[^>]*?\bsrc=)(["'])([^"']+)\2""")
_LINK = re.compile(r"(\]\()([^)\s]+)(\))")
_ANCHOR = re.compile(r"""(<a\s+id=)(["'])(?!user-content-)([^"']+)\2""")
_ALERT = re.compile(r"^> \[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]\s*$", re.M)
_TASK = re.compile(r"^- \[([ xX])\] ", re.M)


def for_pypi(readme: str, ref: str) -> str:
    """`readme` with relative images and links made absolute, for the commit or tag `ref`."""
    raw = f"https://raw.githubusercontent.com/{REPO}/{ref}/"
    blob = f"https://github.com/{REPO}/blob/{ref}/"

    def image(match: re.Match) -> str:
        url = match.group(3)
        return match.group(0) if _ABSOLUTE.match(url) else f"{match.group(1)}{match.group(2)}{raw}{url}{match.group(2)}"

    def link(match: re.Match) -> str:
        url = match.group(2)
        return match.group(0) if _ABSOLUTE.match(url) else f"{match.group(1)}{blob}{url}{match.group(3)}"

    # PyPI drops <picture> and <source>: keep the one image inside, the dark banner
    text = _PICTURE.sub(lambda m: m.group(1), readme)
    text = _SRC.sub(image, text)
    text = _LINK.sub(link, text)
    # PyPI turns a link to #repo into #user-content-repo, but leaves <a id="repo"> as it is, so
    # the links in the table of contents would find nothing
    text = _ANCHOR.sub(lambda m: f"{m.group(1)}{m.group(2)}user-content-{m.group(3)}{m.group(2)}", text)
    # PyPI gives GitHub's alert boxes no styling at all, and draws a bullet next to every checkbox
    text = _ALERT.sub(lambda m: f"> **{m.group(1).capitalize()}**\n>", text)
    return _TASK.sub(lambda m: "- " if m.group(1) != " " else "- planned: ", text)


if __name__ == "__main__":
    path = Path(__file__).resolve().parent.parent / "README.md"
    path.write_text(for_pypi(path.read_text(encoding="utf-8"), sys.argv[1]), encoding="utf-8", newline="\n")
