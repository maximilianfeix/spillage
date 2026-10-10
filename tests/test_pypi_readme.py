"""The README as PyPI gets it: `.github/pypi_readme.py`, run by the release workflow before the build."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("pypi_readme", ROOT / ".github" / "pypi_readme.py")
pypi_readme = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pypi_readme)

RAW = "https://raw.githubusercontent.com/maximilianfeix/spillage/v1.2.3/"
BLOB = "https://github.com/maximilianfeix/spillage/blob/v1.2.3/"


def test_relative_images_and_links_point_at_the_tag():
    text = pypi_readme.for_pypi(
        '<img src="docs/demo.svg" alt="demo" width="860">\n'
        "[license](LICENSE) and [the workflow](.github/workflows/release.yml)\n"
        "[![Python](https://img.shields.io/badge/python-3.9)](pyproject.toml)\n",
        "v1.2.3",
    )
    assert f'<img src="{RAW}docs/demo.svg" alt="demo" width="860">' in text
    assert f"[license]({BLOB}LICENSE)" in text and f"[the workflow]({BLOB}.github/workflows/release.yml)" in text
    assert f"](https://img.shields.io/badge/python-3.9)]({BLOB}pyproject.toml)" in text


def test_absolute_links_and_anchors_stay():
    text = "[site](https://example.com) [install](#install) [mail](mailto:a@example.com)\n"
    assert pypi_readme.for_pypi(text, "v1.2.3") == text


def test_picture_becomes_its_image():
    text = pypi_readme.for_pypi(
        '<picture>\n  <source media="(prefers-color-scheme: dark)" srcset="docs/banner-dark.svg">\n'
        '  <img src="docs/banner-dark.svg" alt="banner" width="100%">\n</picture>\n',
        "v1.2.3",
    )
    assert text == f'<img src="{RAW}docs/banner-dark.svg" alt="banner" width="100%">\n'


def test_anchors_get_the_prefix_pypi_gives_the_links():
    assert pypi_readme.for_pypi('<a id="repo"></a>', "v1") == '<a id="user-content-repo"></a>'


def test_nothing_relative_is_left_in_the_real_readme():
    text = pypi_readme.for_pypi((ROOT / "README.md").read_text(encoding="utf-8"), "v1.2.3")
    assert "<picture>" not in text and "<source" not in text
    images = re.findall(r"""<img\b[^>]*?\bsrc=["']([^"']+)""", text)
    links = re.findall(r"\]\(([^)\s]+)\)", text)
    assert images and all(url.startswith("https://") for url in images)
    assert [url for url in links if not url.startswith(("https://", "#", "mailto:"))] == []
    # every link in the page finds its anchor, the way PyPI rewrites them
    anchors = set(re.findall(r'<a id="user-content-([^"]+)"', text))
    assert {url[1:] for url in links if url.startswith("#")} <= anchors


def test_alerts_and_task_lists_in_a_form_pypi_shows_well():
    text = pypi_readme.for_pypi("> [!IMPORTANT]\n> Rotate first.\n\n- [x] done\n- [ ] later\n", "v1")
    assert text == "> **Important**\n>\n> Rotate first.\n\n- done\n- planned: later\n"
