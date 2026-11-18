"""Run the sample system through every RMF step.

Each step calls one of the tools as a separate process, exactly as a user would
from the command line, and writes into its own numbered folder under the output
directory. Glue steps (``stitch``) are plain Python and are recorded too.

Step order follows the work, not the step numbering in SP 800-37: the boundary
check (Prepare, task P-11) needs the SSP inventory, so it runs after the SSP is
generated. The README's diagram shows both orders.
"""

from __future__ import annotations

import json
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import date
from importlib import metadata
from pathlib import Path
from typing import Any

from rmf_toolchain.stitch import align_system_id, merge_categorization, system_id

ACCOUNT = "111122223333"
REGION = "us-east-1"
SYSTEM = "SYNTHETIC Case Management System (CMS-DEMO)"

# tool -> (how to run it, distribution name, repository)
TOOLS: dict[str, tuple[list[str], str, str]] = {
    "security-categorizer": (["-m", "security_categorizer"], "security-categorizer", "security-categorizer"),
    "oscal-ssp-generator": (["-m", "oscal_ssp_generator"], "oscal-ssp-generator", "oscal-ssp-generator"),
    "boundary-drift-detector": (["-m", "boundary_drift_detector"], "boundary-drift-detector",
                                "boundary-drift-detector"),
    "fedramp-control-validator": (["-m", "fedramp_control_validator"], "fedramp-control-validator",
                                  "fedramp-control-validator"),
    # poam-generator has no __main__ module; call its click group directly.
    "poam-generator": (["-c", "from poam_generator.cli import cli; cli(prog_name='poam')"], "poam-generator",
                       "poam-generator"),
    "stig-poam-builder": (["-m", "stig_poam_builder"], "stig-poam-builder", "stig-poam-builder"),
    "ato-readiness-checker": (["-m", "ato_readiness_checker"], "ato-readiness-checker", "ato-readiness-checker"),
}  # fmt: skip


def tool_version(tool: str) -> str:
    dist = TOOLS[tool][1]
    try:
        return metadata.version(dist)
    except metadata.PackageNotFoundError:
        return "source (not installed)"


def show(cmd: list[str]) -> str:
    """A command as you'd type it; a one-item list is a note, shown as is."""
    return cmd[0] if len(cmd) == 1 else shlex.join(cmd)


@dataclass
class StepResult:
    number: int
    name: str
    rmf_step: str
    tool: str
    commands: list[list[str]] = field(default_factory=list)
    exit_codes: list[int] = field(default_factory=list)
    outputs: list[str] = field(default_factory=list)
    headline: str = ""
    ok: bool = True
    seconds: float = 0.0
    version: str = ""

    def to_dict(self) -> dict:
        return {
            "number": self.number,
            "name": self.name,
            "rmf_step": self.rmf_step,
            "tool": self.tool,
            "version": self.version,
            "commands": [show(c) for c in self.commands],
            "exit_codes": self.exit_codes,
            "outputs": self.outputs,
            "headline": self.headline,
            "ok": self.ok,
            "seconds": round(self.seconds, 2),
        }


class StepFailed(RuntimeError):
    pass


class Pipeline:
    def __init__(self, inputs: Path, out: Path, as_of: date, python: str = sys.executable):
        self.inputs = Path(inputs)
        self.out = Path(out)
        self.as_of = as_of
        self.timestamp = f"{as_of.isoformat()}T12:00:00+00:00"
        self.python = python
        self.results: list[StepResult] = []

    # --- helpers ---------------------------------------------------------------------------

    def _dir(self, name: str) -> Path:
        d = self.out / name
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _run(self, step: StepResult, tool: str, args: list[str], ok_codes: tuple[int, ...] = (0,)) -> str:
        cmd = [self.python, *TOOLS[tool][0], *[str(a) for a in args]]
        shown = [tool, *[str(a) for a in args]]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False, encoding="utf-8", errors="replace")
        log = self.out / step.name / "log.txt"
        with log.open("a", encoding="utf-8") as f:
            f.write(f"$ {show(shown)}\n{proc.stdout}{proc.stderr}\n[exit {proc.returncode}]\n\n")
        step.commands.append(shown)
        step.exit_codes.append(proc.returncode)
        if proc.returncode not in ok_codes:
            step.ok = False
            raise StepFailed(f"{step.name}: {tool} exited {proc.returncode} (see {log})")
        return proc.stdout

    def _rel(self, path: Path) -> str:
        return path.relative_to(self.out).as_posix()

    @staticmethod
    def _load(path: Path) -> Any:
        return json.loads(path.read_text(encoding="utf-8"))

    @staticmethod
    def _dump(path: Path, doc: Any) -> None:
        path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    def _step(self, number: int, name: str, rmf_step: str, tool: str) -> StepResult:
        r = StepResult(number, name, rmf_step, tool, version=tool_version(tool) if tool in TOOLS else "")
        self.results.append(r)
        self._dir(name)
        return r

    # --- steps -------------------------------------------------------------------------------

    def categorize(self) -> None:
        s = self._step(1, "1-categorize", "Categorize", "security-categorizer")
        d = self.out / s.name
        self._run(s, "security-categorizer", ["categorize", self.inputs / "system.yaml", "-o", d,
                                              "--timestamp", self.timestamp])  # fmt: skip
        c = self._load(d / "categorization.json")
        s.outputs = [
            self._rel(d / n) for n in ("categorization.md", "categorization.json", "system-characteristics.json")
        ]
        sc = c["security_category"]
        s.headline = (
            f"{c['overall_impact_level'].capitalize()} system: C={sc['confidentiality']}, I={sc['integrity']}, "
            f"A={sc['availability']}; {len(c['information_types'])} information types"
        )

    def select(self) -> None:
        s = self._step(2, "2-select", "Select", "security-categorizer")
        src, d = self.out / "1-categorize", self.out / s.name
        for name in ("baseline-profile.json", "baseline.txt"):
            shutil.copyfile(src / name, d / name)
        c = self._load(src / "categorization.json")["baseline"]
        s.commands.append(["(baseline selected by security-categorizer in step 1)"])
        s.outputs = [self._rel(d / "baseline-profile.json"), self._rel(d / "baseline.txt")]
        s.headline = f"{c['name']}: {c['control_count']} controls (OSCAL profile)"

    def implement(self) -> None:
        s = self._step(3, "3-implement", "Implement", "oscal-ssp-generator")
        d = self.out / s.name
        raw = d / "ssp-generated.json"
        self._run(s, "oscal-ssp-generator", [self.inputs / "terraform.tfstate", "-o", raw, "--no-banner"])
        fragment = self._load(self.out / "1-categorize" / "system-characteristics.json")
        ssp = merge_categorization(self._load(raw), fragment, "../2-select/baseline-profile.json")
        self._dump(d / "ssp.json", ssp)
        s.commands.append(["(stitch) merge categorization and baseline into the SSP"])
        root = ssp["system-security-plan"]
        s.outputs = [self._rel(raw), self._rel(d / "ssp.json")]
        s.headline = (
            f"Draft SSP: {len(root['control-implementation']['implemented-requirements'])} controls with "
            f"implementation statements, "
            f"{len(root['system-implementation'].get('inventory-items', []))} inventory items"
        )

    def _drift(self, s: StepResult, inventory: Path, d: Path) -> dict:
        self._run(
            s,
            "boundary-drift-detector",
            ["check", "--declared", self.out / "3-implement" / "ssp.json", "--actual", inventory,
             "--region", REGION, "--account", ACCOUNT, "--expect-encrypted", "true",
             "-o", d, "--timestamp", self.timestamp],
        )  # fmt: skip
        return self._load(d / "drift-report.json")

    def prepare_boundary(self) -> None:
        s = self._step(4, "4-prepare-boundary", "Prepare (boundary, task P-11)", "boundary-drift-detector")
        d = self.out / s.name
        r = self._drift(s, self.inputs / "aws-config-inventory.json", d)
        s.outputs = [self._rel(d / n) for n in ("drift-report.md", "drift.oscal.json")]
        k = r["drift_by_kind"]
        s.headline = (
            f"{r['matched']}/{r['boundary']['declared_resources']} declared resources found; "
            f"{k['undeclared']} undeclared, {k['missing']} missing, {k['encryption']} encryption, "
            f"{k['unverified']} unverified"
        )

    def assess(self) -> None:
        s = self._step(5, "5-assess", "Assess", "fedramp-control-validator")
        d = self.out / s.name
        self._run(s, "fedramp-control-validator", [self.inputs / "aws-config-findings.json", "-o",
                                                   d / "assessment-results.json", "-g", d / "gap-report.json",
                                                   "--no-banner"])  # fmt: skip
        ar = self._load(d / "assessment-results.json")["assessment-results"]["results"][0]
        props = {p["name"]: p["value"] for p in ar.get("props", [])}
        findings = ar.get("findings", [])
        bad = sum(1 for f in findings if f["target"]["status"]["state"] == "not-satisfied")
        s.outputs = [self._rel(d / "assessment-results.json"), self._rel(d / "gap-report.json")]
        s.headline = f"{len(findings)} controls assessed, {bad} not satisfied; score {props.get('overall-score', '?')}%"

    def poam(self) -> None:
        s = self._step(6, "6-poam", "Assess → POA&M", "poam-generator")
        d = self.out / s.name
        self._run(s, "poam-generator", ["generate", "-i", self.inputs / "poam-findings.json",
                                        "-o", d / "poam-generator.raw.json", "--format", "oscal"])  # fmt: skip
        s.version = (
            f"poam-generator {tool_version('poam-generator')}; stig-poam-builder {tool_version('stig-poam-builder')}"
        )
        self._run(s, "stig-poam-builder", ["build", self.inputs / "stig", "--cci-list",
                                           self.inputs / "cci" / "U_CCI_List_SAMPLE.xml", "--out", d / "stig",
                                           "--system", SYSTEM, "--as-of", self.as_of.isoformat()])  # fmt: skip
        sid = system_id(self._load(self.out / "3-implement" / "ssp.json"))
        stig_oscal = next((d / "stig").glob("*.oscal.json"))
        counts = []
        for src, name in (
            (d / "poam-generator.raw.json", "poam-generator.oscal.json"),
            (stig_oscal, "stig-poam.oscal.json"),
        ):
            doc = align_system_id(self._load(src), sid)
            self._dump(d / name, doc)
            counts.append(len(doc["plan-of-action-and-milestones"]["poam-items"]))
        s.commands.append(["(stitch) set both POA&Ms' system-id to the SSP's"])
        s.tool = "poam-generator + stig-poam-builder"
        s.outputs = [self._rel(d / "poam-generator.oscal.json"), self._rel(d / "stig-poam.oscal.json")]
        s.headline = f"{counts[0]} POA&M items from assessment findings, {counts[1]} from STIG checklists and ACAS"

    def authorize(self) -> None:
        s = self._step(7, "7-authorize", "Authorize", "ato-readiness-checker")
        d = self.out / s.name
        o = self.out
        self._run(
            s,
            "ato-readiness-checker",
            ["check", "--ssp", o / "3-implement/ssp.json",
             "--ar", o / "5-assess/assessment-results.json", "--ar", o / "4-prepare-boundary/drift.oscal.json",
             "--poam", o / "6-poam/poam-generator.oscal.json", "--poam", o / "6-poam/stig-poam.oscal.json",
             "--baseline", o / "2-select/baseline-profile.json", "--as-of", self.as_of.isoformat(),
             "--brief", "--oscal", "-o", d, "-q"],
        )  # fmt: skip
        r = self._load(d / "readiness-report.json")
        c, risk = r["issue_counts"], r["risk_issue_counts"]
        uncovered = next(x["failed"] for x in r["checks"] if x["check_id"] == "CTRL-001")
        s.outputs = [
            self._rel(d / n) for n in ("readiness-report.md", "ao-brief-draft.md", "readiness-review.oscal.json")
        ]
        s.headline = (
            f"{r['readiness']['level']} (score {r['readiness']['score']}): {c['critical']} critical and "
            f"{c['high']} high package issues ({uncovered} baseline controls the infrastructure-generated SSP "
            f"doesn't address yet); {risk['critical'] + risk['high']} open Critical/High weaknesses for the AO"
        )

    def monitor(self) -> None:
        s = self._step(8, "8-monitor", "Monitor", "boundary-drift-detector + poam-generator")
        d = self.out / s.name
        s.version = (
            f"boundary-drift-detector {tool_version('boundary-drift-detector')}; "
            f"poam-generator {tool_version('poam-generator')}"
        )
        r = self._drift(s, self.inputs / "aws-config-inventory-day30.json", d / "boundary-day30")
        db = d / "poam-tracker.db"
        if db.exists():
            db.unlink()
        self._run(s, "poam-generator", ["track", "-i", self.inputs / "poam-findings.json", "--db", db])
        self._run(s, "poam-generator", ["status", "--db", db])
        k = r["drift_by_kind"]
        s.outputs = [self._rel(d / "boundary-day30" / "drift-report.md"), self._rel(db)]
        s.headline = (
            f"Day 30 inventory: {k['undeclared']} undeclared, {k['missing']} missing; "
            "POA&M loaded into the SQLite tracker with its audit trail"
        )

    # --- run ---------------------------------------------------------------------------------

    def run(self) -> list[StepResult]:
        if self.out.exists():
            shutil.rmtree(self.out)
        self.out.mkdir(parents=True)
        for fn in (self.categorize, self.select, self.implement, self.prepare_boundary, self.assess, self.poam,
                   self.authorize, self.monitor):  # fmt: skip
            start = time.monotonic()
            try:
                fn()
            finally:
                self.results[-1].seconds = time.monotonic() - start
        return self.results
