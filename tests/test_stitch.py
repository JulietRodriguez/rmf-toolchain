import copy

import pytest

from rmf_toolchain.stitch import NS, align_system_id, merge_categorization, system_id

SSP = {
    "system-security-plan": {
        "metadata": {"title": "t", "remarks": "generated"},
        "import-profile": {"href": "https://example.com/fedramp-moderate.json"},
        "system-characteristics": {
            "system-ids": [{"identifier-type": "https://ietf.org/rfc/rfc4122", "id": "sys-1"}],
            "security-sensitivity-level": "fips-199-moderate",
            "system-information": {"information-types": [{"title": "placeholder", "description": "x"}]},
            "security-impact-level": {"security-objective-confidentiality": "fips-199-moderate"},
            "props": [{"name": "old", "ns": NS, "value": "drop me"}, {"name": "keep", "value": "1"}],
        },
    }
}
FRAGMENT = {
    "security-sensitivity-level": "fips-199-high",
    "system-information": {"information-types": [{"title": "Case records", "description": "real"}]},
    "security-impact-level": {"security-objective-confidentiality": "fips-199-high"},
    "props": [{"name": "categorization-mode", "ns": "https://x", "value": "federal"}],
}


def test_merge_categorization_replaces_only_categorization():
    original = copy.deepcopy(SSP)
    out = merge_categorization(SSP, FRAGMENT, "../2-select/baseline-profile.json")
    assert original == SSP  # input untouched
    chars = out["system-security-plan"]["system-characteristics"]
    assert chars["security-sensitivity-level"] == "fips-199-high"
    assert chars["system-information"]["information-types"][0]["title"] == "Case records"
    assert chars["system-ids"] == SSP["system-security-plan"]["system-characteristics"]["system-ids"]
    names = [p["name"] for p in chars["props"]]
    assert names == ["keep", "categorization-mode", "categorization-source"]
    root = out["system-security-plan"]
    assert root["import-profile"] == {"href": "../2-select/baseline-profile.json"}
    assert root["metadata"]["remarks"].startswith("generated\n\nrmf-toolchain:")


def test_merge_requires_full_fragment():
    with pytest.raises(ValueError, match="security-impact-level"):
        merge_categorization(SSP, {k: v for k, v in FRAGMENT.items() if k != "security-impact-level"}, "b.json")


def test_system_id_and_alignment():
    sid = system_id(SSP)
    assert sid["id"] == "sys-1"
    poam = {"plan-of-action-and-milestones": {"metadata": {"title": "p"}, "system-id": {"id": "other"}}}
    out = align_system_id(poam, sid)
    root = out["plan-of-action-and-milestones"]
    assert root["system-id"]["id"] == "sys-1" and "was other" in root["metadata"]["remarks"]
    again = align_system_id(out, sid)
    assert again["plan-of-action-and-milestones"]["metadata"]["remarks"].count("rmf-toolchain") == 1


def test_system_id_missing():
    with pytest.raises(ValueError, match="no system-ids"):
        system_id({"system-security-plan": {"system-characteristics": {}}})
