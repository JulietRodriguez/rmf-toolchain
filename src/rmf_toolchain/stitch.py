"""Glue between the tools: the small edits that make their outputs one package.

Each tool writes valid OSCAL on its own, but they were built separately, so two
things don't line up out of the box:

1. oscal-ssp-generator builds the SSP from infrastructure and writes a placeholder
   categorization. security-categorizer produces the real one. ``merge_categorization``
   copies the categorizer's system-characteristics content (information types,
   impact levels, sensitivity level) into the SSP and points its import-profile at
   the selected baseline.
2. The POA&M tools don't know the SSP's system ID. ``align_system_id`` sets each
   POA&M's system-id to the SSP's, so the package refers to one system.

Every edit is recorded in the SSP or POA&M metadata remarks, so a reader can see
what the toolchain changed. Nothing else in the tools' output is modified.
"""

from __future__ import annotations

import copy
from typing import Any

CATEGORIZATION_KEYS = ("security-sensitivity-level", "system-information", "security-impact-level")
NS = "https://github.com/JulietRodriguez/rmf-toolchain/ns/oscal"


def _note(metadata: dict[str, Any], text: str) -> None:
    existing = metadata.get("remarks", "")
    metadata["remarks"] = f"{existing}\n\n{text}".strip() if existing else text


def merge_categorization(ssp: dict, fragment: dict, baseline_href: str) -> dict:
    """Return a copy of ``ssp`` with the categorizer's results and the baseline profile."""
    out = copy.deepcopy(ssp)
    root = out["system-security-plan"]
    chars = root["system-characteristics"]
    for key in CATEGORIZATION_KEYS:
        if key not in fragment:
            raise ValueError(f"categorization fragment has no {key!r}")
        chars[key] = copy.deepcopy(fragment[key])
    props = [p for p in chars.get("props", []) if p.get("ns") != NS]
    for p in fragment.get("props", []):
        props.append({**p})
    props.append({"name": "categorization-source", "ns": NS, "value": "security-categorizer"})
    chars["props"] = props
    root["import-profile"] = {"href": baseline_href}
    _note(
        root["metadata"],
        "rmf-toolchain: system-information, security-impact-level and security-sensitivity-level come from "
        f"security-categorizer; import-profile points at the selected baseline ({baseline_href}).",
    )
    return out


def system_id(ssp: dict) -> dict:
    ids = ssp["system-security-plan"]["system-characteristics"].get("system-ids") or []
    if not ids:
        raise ValueError("the SSP has no system-ids")
    return copy.deepcopy(ids[0])


def align_system_id(poam: dict, sid: dict) -> dict:
    """Return a copy of ``poam`` whose system-id is the SSP's."""
    out = copy.deepcopy(poam)
    root = out["plan-of-action-and-milestones"]
    old = root.get("system-id", {}).get("id")
    root["system-id"] = copy.deepcopy(sid)
    if old != sid.get("id"):
        _note(root["metadata"], f"rmf-toolchain: system-id set to the SSP's ({sid.get('id')}); was {old}.")
    return out
