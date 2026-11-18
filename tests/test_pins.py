"""requirements-tools.txt pins every tool the pipeline runs, to a tag, and its tag table agrees."""

import re
from pathlib import Path

from rmf_toolchain.pipeline import TOOLS

ROOT = Path(__file__).resolve().parents[1]
TEXT = (ROOT / "requirements-tools.txt").read_text()


def _pins() -> dict[str, str]:
    pins = {}
    for line in TEXT.splitlines():
        if not line or line.startswith("#"):
            continue
        m = re.fullmatch(r"([\w-]+) @ git\+https://github\.com/JulietRodriguez/([\w-]+)@(v\d+\.\d+\.\d+)", line)
        assert m, f"not pinned to a release tag: {line}"
        assert m.group(1) == m.group(2), line
        pins[m.group(1)] = m.group(3)
    return pins


def _table() -> dict[str, tuple[str, str]]:
    rows = re.findall(r"^#\s+([\w-]+)\s+(v\d+\.\d+\.\d+)\s+([0-9a-f]{7,40})$", TEXT, flags=re.M)
    return {name: (tag, sha) for name, tag, sha in rows}


def test_every_tool_is_pinned_to_a_tag():
    assert set(_pins()) == {dist for _, dist, _ in TOOLS.values()}


def test_tag_table_matches_pins():
    assert {name: tag for name, (tag, _) in _table().items()} == _pins()
