"""Pipeline summary (Markdown + JSON) and OSCAL validation of every output."""

from __future__ import annotations

import json
from pathlib import Path

from rmf_toolchain import __version__
from rmf_toolchain.pipeline import Pipeline, show

SCHEMAS = {
    "system-security-plan": "oscal_ssp_schema.json",
    "assessment-results": "oscal_assessment-results_schema.json",
    "plan-of-action-and-milestones": "oscal_poam_schema.json",
    "profile": "oscal_profile_schema.json",
}
_REWRITES = {r"\p{L}": r"[^\W\d_]", r"\p{N}": r"\d"}


def _rewrite(node):
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            if k == "pattern" and isinstance(v, str):
                for a, b in _REWRITES.items():
                    v = v.replace(a, b)
            out[k] = _rewrite(v)
        return out
    if isinstance(node, list):
        return [_rewrite(v) for v in node]
    return node


def validate_outputs(out: Path, schema_dir: Path) -> list[dict]:
    """Validate every OSCAL JSON file under ``out`` against NIST's schema for its model.

    NIST's schemas use \\p{L} and \\p{N} in regex patterns, which Python's ``re``
    doesn't support; those two classes are translated to equivalents first.
    """
    from jsonschema import Draft7Validator

    validators: dict[str, Draft7Validator] = {}
    results = []
    for path in sorted(out.rglob("*.json")):
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        model = next((m for m in SCHEMAS if isinstance(doc, dict) and m in doc), None)
        if model is None:
            continue
        if model not in validators:
            schema = json.loads((schema_dir / SCHEMAS[model]).read_text(encoding="utf-8"))
            validators[model] = Draft7Validator(_rewrite(schema))
        errors = [f"{'/'.join(map(str, e.absolute_path))}: {e.message}" for e in validators[model].iter_errors(doc)]
        results.append({"file": path.relative_to(out).as_posix(), "model": model, "errors": errors[:10],
                        "valid": not errors})  # fmt: skip
    return results


def summary_dict(p: Pipeline, validation: list[dict] | None) -> dict:
    return {
        "toolchain": {"name": "rmf-toolchain", "version": __version__},
        "system": "SYNTHETIC Case Management System (CMS-DEMO)",
        "as_of": p.as_of.isoformat(),
        "steps": [r.to_dict() for r in p.results],
        "oscal_validation": validation,
    }


def summary_markdown(p: Pipeline, validation: list[dict] | None) -> str:
    out: list[str] = []
    w = out.append
    w("# RMF pipeline run: SYNTHETIC Case Management System (CMS-DEMO)")
    w("")
    w(f"As of {p.as_of.isoformat()}. Every input is synthetic. Each step ran the tool's own command line.")
    w("")
    w("| # | RMF step | Tool (version) | Result | Outputs |")
    w("|---|---|---|---|---|")
    for r in p.results:
        version = r.version if ";" in r.version else f"{r.tool} {r.version}"
        links = "<br>".join(f"[{Path(o).name}]({o})" for o in r.outputs)
        status = "" if r.ok else "**FAILED** "
        w(f"| {r.number} | {r.rmf_step} | {version} | {status}{r.headline} | {links} |")
    w("")
    if validation is not None:
        bad = [v for v in validation if not v["valid"]]
        w(f"## OSCAL validation: {len(validation) - len(bad)} of {len(validation)} documents valid")
        w("")
        w("Each OSCAL document the pipeline produced, checked against NIST's official OSCAL 1.1.2 JSON schema.")
        w("")
        w("| File | Model | Valid |")
        w("|---|---|---|")
        for v in validation:
            w(f"| `{v['file']}` | {v['model']} | {'yes' if v['valid'] else 'NO: ' + v['errors'][0]} |")
        w("")
    w("## Commands")
    w("")
    for r in p.results:
        w(f"**{r.number}. {r.rmf_step}**")
        w("")
        w("```")
        for c in r.commands:
            w(show(c))
        w("```")
        w("")
    w("The readiness score and level in step 7 are ato-readiness-checker's own measures; only the Authorizing")
    w("Official makes the authorization decision.")
    w("")
    return "\n".join(out)
