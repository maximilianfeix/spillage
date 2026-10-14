"""Walk parsed JSON and yield every string in it together with its path."""

from __future__ import annotations

from typing import Any, Iterator, Optional, Tuple

# Keys whose values are opaque blobs: thinking signatures, encrypted reasoning, base64 media.
# Scanning them only produces noise and costs time.
SKIP_KEYS = frozenset({"signature", "encrypted_content", "data", "image_url", "base64"})
MAX_STRING = 2_000_000

Path = Tuple[Any, ...]


def _is_binary_block(node: dict) -> bool:
    source = node.get("source")
    return (
        node.get("type") in ("image", "document")
        and isinstance(source, dict)
        and source.get("type") == "base64"
    )


def iter_strings(node: Any, path: Path = (), max_string: Optional[int] = MAX_STRING) -> Iterator[Tuple[Path, str]]:
    """Depth-first (path, string) pairs, in document order. Strings longer than `max_string` are
    left out, which is right for running rules over them and wrong for finding the place of a
    match that is already known: pass None there."""
    stack = [(path, node)]
    while stack:
        here, value = stack.pop()
        if isinstance(value, str):
            if value and (max_string is None or len(value) <= max_string):
                yield here, value
        elif isinstance(value, dict):
            if _is_binary_block(value):
                continue
            for key, child in reversed(list(value.items())):
                if key in SKIP_KEYS and isinstance(child, str) and len(child) > 256:
                    continue
                stack.append((here + (key,), child))
        elif isinstance(value, list):
            for i in range(len(value) - 1, -1, -1):
                stack.append((here + (i,), value[i]))


def get_path(node: Any, path: Path) -> Any:
    for part in path:
        node = node[part]
    return node


def set_path(node: Any, path: Path, value: Any) -> Any:
    """Set a value by path and return the (possibly new) root."""
    if not path:
        return value
    get_path(node, path[:-1])[path[-1]] = value
    return node


def format_path(path: Path) -> str:
    out = ""
    for part in path:
        if isinstance(part, int):
            out += f"[{part}]"
        elif part.isidentifier():
            out += f".{part}" if out else part
        else:
            out += f"[{part!r}]"
    return out
