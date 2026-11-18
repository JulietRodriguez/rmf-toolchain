# Design notes

Plain-language notes on why rmf-toolchain works the way it does. Written to be easy to
explain out loud.

## What it is, in one sentence

A pipeline that takes one made-up system through every RMF step using seven separate
tools, passes OSCAL documents from one to the next, and checks on every push that the
result is a valid, consistent package.

## Why build it

Each tool proves something on its own: you can categorize a system, generate an SSP,
assess controls, build a POA&M, check a package. But the hard part of RMF in practice is
the handoff. A categorization memo says Moderate while the SSP still says Low. The POA&M
uses a different system name. The assessment covered 22 controls and the baseline has 340.
These problems usually surface late, in front of the AO. Running the handoffs as code
makes them surface on every push instead.

## How it's put together

- **`pipeline.py`** runs the eight steps in order. Each step calls a tool's real command
  line, writes the tool's output and a `log.txt` with the exact
  command, and records a one-line result. If a tool exits with an unexpected code, the
  pipeline stops and says which step failed.
- **`stitch.py`** holds the only two edits the pipeline makes to the tools' output:
  copying the categorization into the SSP, and setting each POA&M's system ID to the
  SSP's. Both edits are written into the documents' metadata remarks, so a reviewer can
  see what the toolchain changed and why.
- **`report.py`** validates every JSON file the run produced against NIST's OSCAL schema
  for its model, and writes `out/README.md` and `out/summary.json`. In GitHub Actions the
  same summary goes on the run page.

## Choices and the reasons for them

**Real command lines, not imports.** If the pipeline imported each tool's Python
functions, it could pass while the documented CLI was broken. Calling the CLI tests what
a user would actually run.

**Pinned versions.** The pipeline installs each tool from a release tag. Without pins, a
change in one tool could silently change every result here. The pins file lists the
commit for each tag, and CI checks that each tag still points at that commit.

**Fixed date.** POA&M due dates and "overdue" checks depend on today's date. The pipeline
uses a fixed `--as-of` date (2026-11-17) by default, so the same inputs always give the
same outputs. You can pass another date.

**Validate everything.** The pipeline doesn't trust that a tool's output is valid OSCAL
just because the tool says so. It downloads NIST's schemas in CI, checks their SHA-256
values, and validates all 12 documents.

**Small, visible glue.** It would be easy to "fix" the tools' outputs until the readiness
check came out clean. That would hide real gaps. The pipeline only joins the documents;
everything else, including the gaps, is what the tools actually produced.

## Reading the result

The readiness check comes out NEEDS WORK, and that's the honest answer. The SSP was
generated from infrastructure, so it has statements for 20 controls while the selected
baseline has 340. The STIG-based POA&M and the AWS Config assessment cover different
evidence, so some findings have no POA&M item and some POA&M items have no finding. The
checker lists each one. Those are the places where a person (the ISSO, the control
owners, the assessor) still has to do the work.

The score is a measure of the package, not of the system's security, and not an
authorization decision. Only the AO decides.

## What I'd do next

- A second sample system that comes out READY FOR REVIEW, to show the gate passing.
- Map STIG and ACAS findings to the assessment's controls, so TRC-001 and TRC-002 close.
- Run the Monitor step on a schedule against several inventories and feed the results
  into continuous-monitoring-dashboard.
