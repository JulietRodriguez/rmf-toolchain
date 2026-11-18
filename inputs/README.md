# Inputs

Everything here is **synthetic**. No real system, account, person or finding is described.
The AWS account ID `111122223333` is the placeholder AWS uses in its own documentation.

| File | Used by (step) | What it is | Source |
|---|---|---|---|
| `system.yaml` | security-categorizer (1, 2) | Categorization worksheet: 2 SP 800-60 information types (one with a documented integrity adjustment), 1 custom organization type, PII flag | `tools/make_inputs.py` |
| `terraform.tfstate` | oscal-ssp-generator (3) | 13 Terraform resources: 12 assets plus one S3 encryption-settings resource | `tools/make_inputs.py` |
| `aws-config-inventory.json` | boundary-drift-detector (4) | Day-0 AWS Config inventory: the 12 declared assets, one undeclared S3 bucket (`cms-demo-export-tmp`), one compliance record that isn't an asset | `tools/make_inputs.py` |
| `aws-config-findings.json` | fedramp-control-validator (5) | 20 AWS Config rule evaluations (15 compliant, 5 non-compliant) | `tools/make_inputs.py` |
| `poam-findings.json` | poam-generator (6, 8) | 5 weaknesses (SC-7, AU-12, IA-5, SC-28, CM-8) | `tools/make_inputs.py` |
| `aws-config-inventory-day30.json` | boundary-drift-detector (8) | Day-30 inventory: web01 replaced by an undeclared web02, security group fixed | `tools/make_inputs.py` |
| `stig/*.ckl`, `stig/*.cklb`, `stig/monthly_scan.nessus` | stig-poam-builder (6) | Three demo STIG checklists and one ACAS scan | Copied from [stig-poam-builder](https://github.com/JulietRodriguez/stig-poam-builder)'s samples |
| `cci/U_CCI_List_SAMPLE.xml` | stig-poam-builder (6) | Sample CCI-to-control list | Copied from stig-poam-builder's samples |

The generated files are deterministic. `python tools/make_inputs.py` rewrites them;
`python tools/make_inputs.py --check` (run in CI) fails if a committed file differs from
what the script produces.
