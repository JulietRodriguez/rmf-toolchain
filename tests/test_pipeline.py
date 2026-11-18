"""The pipeline runner, the summary, and (when the tools are installed) a full run."""

import importlib.util
import json
import subprocess
import sys
from datetime import date
from pathlib import Path

import pytest

from rmf_toolchain import pipeline as pl
from rmf_toolchain.cli import main
from rmf_toolchain.pipeline import Pipeline, StepFailed, StepResult, tool_version
from rmf_toolchain.report import summary_markdown, validate_outputs

ROOT = Path(__file__).resolve().parents[1]
TOOL_MODULES = ["security_categorizer", "oscal_ssp_generator", "boundary_drift_detector", "fedramp_control_validator",
                "poam_generator", "stig_poam_builder", "ato_readiness_checker"]  # fmt: skip
TOOLS_INSTALLED = all(importlib.util.find_spec(m) for m in TOOL_MODULES)


def test_run_records_failure_and_log(tmp_path, monkeypatch):
    monkeypatch.setitem(pl.TOOLS, "fake", (["-c", "import sys; print('boom'); sys.exit(3)"], "fake-dist", "fake"))
    p = Pipeline(tmp_path / "in", tmp_path / "out", date(2026, 11, 17))
    step = p._step(1, "1-x", "Categorize", "fake")
    with pytest.raises(StepFailed, match="exited 3"):
        p._run(step, "fake", ["--flag"])
    assert step.ok is False and step.exit_codes == [3]
    assert "boom" in (tmp_path / "out" / "1-x" / "log.txt").read_text()
    assert step.version == "source (not installed)"


def test_run_accepts_listed_exit_codes(tmp_path, monkeypatch):
    monkeypatch.setitem(pl.TOOLS, "fake", (["-c", "import sys; sys.exit(1)"], "fake-dist", "fake"))
    p = Pipeline(tmp_path / "in", tmp_path / "out", date(2026, 11, 17))
    step = p._step(1, "1-x", "Categorize", "fake")
    p._run(step, "fake", [], ok_codes=(0, 1))
    assert step.ok


def test_tool_version_unknown():
    assert tool_version("poam-generator")  # installed in CI, "source (not installed)" locally


def test_summary_markdown_lists_steps_and_validation(tmp_path):
    p = Pipeline(tmp_path, tmp_path, date(2026, 11, 17))
    p.results = [StepResult(1, "1-categorize", "Categorize", "security-categorizer", outputs=["1-categorize/c.md"],
                            headline="Moderate", version="0.1.0"),
                 StepResult(2, "2-x", "Select", "t", ok=False, headline="broke", version="a 1; b 2")]  # fmt: skip
    md = summary_markdown(p, [{"file": "a.json", "model": "profile", "valid": False, "errors": ["bad"]}])
    assert "| 1 | Categorize | security-categorizer 0.1.0 | Moderate | [c.md](1-categorize/c.md) |" in md
    assert "**FAILED** broke" in md and "| a 1; b 2 |" in md
    assert "0 of 1 documents valid" in md and "NO: bad" in md


def test_validate_outputs(tmp_path):
    good = {"profile": {"uuid": "11111111-1111-4111-8111-111111111111", "metadata": {"title": "t",
            "last-modified": "2026-11-17T12:00:00+00:00", "version": "1", "oscal-version": "1.1.2"},
            "imports": [{"href": "#x", "include-controls": [{"with-ids": ["ac-1"]}]}]}}  # fmt: skip
    (tmp_path / "good.json").write_text(json.dumps(good))
    (tmp_path / "bad.json").write_text(json.dumps({"profile": {"uuid": "x"}}))
    (tmp_path / "other.json").write_text("{not json")
    (tmp_path / "plain.json").write_text("{}")
    res = {r["file"]: r["valid"] for r in validate_outputs(tmp_path, ROOT / "schemas")}
    assert res == {"bad.json": False, "good.json": True}


def test_inputs_are_up_to_date():
    proc = subprocess.run([sys.executable, str(ROOT / "tools" / "make_inputs.py"), "--check"], capture_output=True,
                          text=True, check=False)  # fmt: skip
    assert proc.returncode == 0, proc.stderr


@pytest.mark.skipif(
    not TOOLS_INSTALLED, reason="the pinned tools are not installed (pip install -r requirements-tools.txt)"
)
def test_full_pipeline(tmp_path, capsys):
    out = tmp_path / "out"
    code = main(["run", "--inputs", str(ROOT / "inputs"), "--out", str(out), "--schema-dir", str(ROOT / "schemas")])
    printed = capsys.readouterr().out
    assert code == 0, printed
    summary = json.loads((out / "summary.json").read_text())
    steps = {s["name"]: s for s in summary["steps"]}
    assert len(steps) == 8 and all(s["ok"] for s in steps.values())
    assert steps["1-categorize"]["headline"].startswith("Moderate system")
    assert steps["2-select"]["headline"].startswith("SP 800-53B Moderate + Privacy: 340 controls")
    assert "1 undeclared, 0 missing" in steps["4-prepare-boundary"]["headline"]
    assert steps["7-authorize"]["headline"].startswith(("NOT READY", "NEEDS WORK", "READY FOR REVIEW"))
    assert all(v["valid"] for v in summary["oscal_validation"]) and len(summary["oscal_validation"]) >= 12
    assert (out / "README.md").is_file()
    ssp = json.loads((out / "3-implement" / "ssp.json").read_text())["system-security-plan"]
    sid = ssp["system-characteristics"]["system-ids"][0]["id"]
    for name in ("poam-generator.oscal.json", "stig-poam.oscal.json"):
        poam = json.loads((out / "6-poam" / name).read_text())["plan-of-action-and-milestones"]
        assert poam["system-id"]["id"] == sid


def test_cli_reports_step_failure(tmp_path, capsys):
    code = main(["run", "--inputs", str(tmp_path / "missing"), "--out", str(tmp_path / "out")])
    assert code == 1
    assert "error:" in capsys.readouterr().err
    assert (tmp_path / "out" / "README.md").is_file()
