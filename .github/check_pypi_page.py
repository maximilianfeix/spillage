"""Renders the README the way PyPI will and fails on anything that would be broken there.

`twine check` never renders Markdown, so it can't see a missing image. This uses PyPI's own
renderer (`pip install "readme-renderer[md]"`) on the text `pypi_readme.py` produces:

    python .github/check_pypi_page.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

from pypi_readme import for_pypi
from readme_renderer.markdown import render

readme = Path(__file__).resolve().parent.parent / "README.md"
html = render(for_pypi(readme.read_text(encoding="utf-8"), "main"))
if not html:
    sys.exit("PyPI's renderer could not render the README")
problems = []
ids = set(re.findall(r'\bid="([^"]+)"', html))
for attribute, url in re.findall(r'\b(src|href)="([^"]*)"', html):
    if url.startswith("#"):
        if url[1:] not in ids:
            problems.append(f"link to {url}, but nothing on the page has that id")
    elif not url.startswith(("https://", "http://", "mailto:")):
        problems.append(f'{attribute}="{url}" is relative, PyPI can\'t resolve it')
if "<img" not in html:
    problems.append("no image survived")
for problem in sorted(set(problems)):
    print(f"::error::{problem}")
sys.exit(1 if problems else 0)
