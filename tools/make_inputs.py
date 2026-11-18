"""Build the synthetic inputs in inputs/ for the sample system CMS-DEMO.

    python tools/make_inputs.py            # write
    python tools/make_inputs.py --check    # exit 1 if committed inputs differ

Everything is SYNTHETIC: an invented case management system in AWS's
documentation account 111122223333. The STIG checklists, ACAS scan and CCI list
in inputs/stig and inputs/cci are copied unchanged from stig-poam-builder's
synthetic samples (see inputs/README.md).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INPUTS = ROOT / "inputs"
ACCOUNT = "111122223333"
REGION = "us-east-1"
SYSTEM = "SYNTHETIC Case Management System (CMS-DEMO)"


def arn(service: str, resource: str) -> str:
    return f"arn:aws:{service}:{REGION}:{ACCOUNT}:{resource}"


# name -> (terraform type, AWS Config type, id, arn, extra terraform attributes)
RESOURCES = {
    "case_files": ("aws_s3_bucket", "AWS::S3::Bucket", "cms-demo-case-files", "arn:aws:s3:::cms-demo-case-files", {}),
    "logs": ("aws_s3_bucket", "AWS::S3::Bucket", "cms-demo-logs", "arn:aws:s3:::cms-demo-logs", {}),
    "data_key": ("aws_kms_key", "AWS::KMS::Key", "0a1b2c3d-0000-4000-8000-000000000001",
                 arn("kms", "key/0a1b2c3d-0000-4000-8000-000000000001"), {}),
    "web01": ("aws_instance", "AWS::EC2::Instance", "i-0a1b2c3d4e5f60001", arn("ec2", "instance/i-0a1b2c3d4e5f60001"),
              {"tags": {"Name": "web01"}}),
    "app01": ("aws_instance", "AWS::EC2::Instance", "i-0a1b2c3d4e5f60002", arn("ec2", "instance/i-0a1b2c3d4e5f60002"),
              {"tags": {"Name": "app01"}}),
    "db01": ("aws_instance", "AWS::EC2::Instance", "i-0a1b2c3d4e5f60003", arn("ec2", "instance/i-0a1b2c3d4e5f60003"),
             {"tags": {"Name": "db01"}}),
    "app_sg": ("aws_security_group", "AWS::EC2::SecurityGroup", "sg-0a1b2c3d4e5f60001",
               arn("ec2", "security-group/sg-0a1b2c3d4e5f60001"), {"name": "cms-demo-app"}),
    "alb": ("aws_lb", "AWS::ElasticLoadBalancingV2::LoadBalancer", "cms-demo-alb",
            arn("elasticloadbalancing", "loadbalancer/app/cms-demo-alb/0a1b2c3d4e5f6001"), {"name": "cms-demo-alb"}),
    "app_role": ("aws_iam_role", "AWS::IAM::Role", "cms-demo-app", f"arn:aws:iam::{ACCOUNT}:role/cms-demo-app",
                 {"name": "cms-demo-app"}),
    "trail": ("aws_cloudtrail", "AWS::CloudTrail::Trail", "cms-demo-trail", arn("cloudtrail", "trail/cms-demo-trail"),
              {"name": "cms-demo-trail"}),
    "app_logs": ("aws_cloudwatch_log_group", "AWS::Logs::LogGroup", "/cms-demo/app",
                 arn("logs", "log-group:/cms-demo/app"), {"name": "/cms-demo/app"}),
    "detector": ("aws_guardduty_detector", "AWS::GuardDuty::Detector", "0a1b2c3d4e5f60001a2b3c4d5e6f7a8b",
                 arn("guardduty", "detector/0a1b2c3d4e5f60001a2b3c4d5e6f7a8b"), {}),
}  # fmt: skip


def system_yaml() -> str:
    return f"""# SYNTHETIC sample system for rmf-toolchain (security-categorizer input).
system:
  name: {SYSTEM}
  short_name: CMS-DEMO
  description: Tracks case files and their status for a fictional agency.
mode: federal
processes_pii: true
information_types:
  - id: C.3.5.8            # System and Network Monitoring (M/M/L)
  - id: C.2.1.1            # Corrective Action (L/L/L)
    adjustments:
      - objective: integrity
        level: moderate
        justification: >-
          Corrective-action records drive case closure decisions; undetected changes
          would produce wrong outcomes for the people the cases concern.
  - custom:
      id: ORG-CMS-01
      title: Case records
      confidentiality: moderate
      integrity: moderate
      availability: low
      source: SYNTHETIC agency supplement to SP 800-60
"""


def terraform_state() -> dict:
    resources = []
    for name, (tf_type, _cfg, rid, a, extra) in RESOURCES.items():
        attrs = {"id": rid, "arn": a, "region": REGION, **extra}
        if tf_type == "aws_s3_bucket":
            attrs["bucket"] = rid
        resources.append(
            {
                "mode": "managed",
                "type": tf_type,
                "name": name,
                "provider": 'provider["registry.terraform.io/hashicorp/aws"]',
                "instances": [{"attributes": attrs}],
            }
        )
    resources.append(
        {
            "mode": "managed",
            "type": "aws_s3_bucket_server_side_encryption_configuration",
            "name": "case_files",
            "provider": 'provider["registry.terraform.io/hashicorp/aws"]',
            "instances": [{"attributes": {"id": "cms-demo-case-files", "bucket": "cms-demo-case-files"}}],
        }
    )
    return {
        "version": 4,
        "terraform_version": "1.9.8",
        "serial": 12,
        "lineage": "5b0c6f1e-0000-4000-8000-0000000c3d5d",
        "outputs": {"system_name": {"value": SYSTEM, "type": "string"}},
        "resources": resources,
    }


PAB_ON = {"blockPublicAcls": True, "ignorePublicAcls": True, "blockPublicPolicy": True, "restrictPublicBuckets": True}


def _item(cfg_type, rid, a, name=None, configuration=None, supplementary=None, region=REGION):
    item = {"arn": a, "resourceType": cfg_type, "resourceId": rid, "awsRegion": region, "accountId": ACCOUNT,
            "configuration": configuration or {}, "supplementaryConfiguration": supplementary or {}}  # fmt: skip
    if name:
        item["resourceName"] = name
    return item


def config_inventory(day: int) -> dict:
    """Day 0: what the assessor sees. Day 30: what continuous monitoring sees a month later."""
    items = []
    for name, (_tf, cfg_type, rid, a, extra) in RESOURCES.items():
        if day == 30 and name == "web01":
            continue  # replaced: no longer in the account
        configuration, supplementary = {}, {}
        region = "global" if cfg_type == "AWS::IAM::Role" else REGION
        if cfg_type == "AWS::S3::Bucket":
            supplementary["PublicAccessBlockConfiguration"] = PAB_ON
            if name == "case_files":
                supplementary["ServerSideEncryptionConfiguration"] = {"rules": [{"sse": "aws:kms"}]}
        if cfg_type == "AWS::EC2::Instance":
            configuration = {"privateIpAddress": "10.0.1.10", "networkInterfaces": []}
        if cfg_type == "AWS::EC2::SecurityGroup":
            cidr = "10.0.0.0/16" if day == 30 else "0.0.0.0/0"  # SSH open to the internet on day 0, fixed by day 30
            configuration = {"ipPermissions": [{"fromPort": 22, "toPort": 22, "ipv4Ranges": [{"cidrIp": cidr}]}]}
        if cfg_type == "AWS::ElasticLoadBalancingV2::LoadBalancer":
            configuration = {"scheme": "internet-facing"}
        items.append(_item(cfg_type, rid, a, extra.get("name") or extra.get("tags", {}).get("Name"),
                           configuration, supplementary, region))  # fmt: skip
    if day == 0:
        items.append(_item("AWS::S3::Bucket", "cms-demo-export-tmp", "arn:aws:s3:::cms-demo-export-tmp",
                           "cms-demo-export-tmp", supplementary={"PublicAccessBlockConfiguration": PAB_ON}))  # fmt: skip
    else:
        items.append(_item("AWS::EC2::Instance", "i-0a1b2c3d4e5f60009", arn("ec2", "instance/i-0a1b2c3d4e5f60009"),
                           "web02", configuration={"privateIpAddress": "10.0.1.11", "networkInterfaces": []}))  # fmt: skip
    items.append(_item("AWS::Config::ResourceCompliance", "AWS::S3::Bucket/cms-demo-logs",
                       arn("config", "resource-compliance/AWS::S3::Bucket/cms-demo-logs")))  # fmt: skip
    return {"Results": [json.dumps(i, separators=(",", ":")) for i in items]}


def config_findings() -> dict:
    """AWS Config rule evaluations for fedramp-control-validator."""
    rows = [
        ("iam-password-policy", "AWS::::Account", ACCOUNT, "NON_COMPLIANT", "Password policy minimum length is 8."),
        ("iam-user-mfa-enabled", "AWS::IAM::User", "cms-admin", "COMPLIANT", None),
        ("root-account-mfa-enabled", "AWS::::Account", ACCOUNT, "COMPLIANT", None),
        ("access-keys-rotated", "AWS::IAM::User", "cms-admin", "COMPLIANT", None),
        ("iam-policy-no-statements-with-admin-access", "AWS::IAM::Policy", "cms-demo-app", "COMPLIANT", None),
        ("s3-bucket-server-side-encryption-enabled", "AWS::S3::Bucket", "cms-demo-case-files", "COMPLIANT", None),
        ("s3-bucket-server-side-encryption-enabled", "AWS::S3::Bucket", "cms-demo-logs", "NON_COMPLIANT",
         "No default encryption configuration."),
        ("encrypted-volumes", "AWS::EC2::Volume", "vol-0a1b2c3d4e5f60001", "COMPLIANT", None),
        ("s3-bucket-public-read-prohibited", "AWS::S3::Bucket", "cms-demo-case-files", "COMPLIANT", None),
        ("restricted-ssh", "AWS::EC2::SecurityGroup", "sg-0a1b2c3d4e5f60001", "NON_COMPLIANT",
         "Port 22 open to 0.0.0.0/0."),
        ("ec2-instance-no-public-ip", "AWS::EC2::Instance", "i-0a1b2c3d4e5f60001", "COMPLIANT", None),
        ("cloudtrail-enabled", "AWS::::Account", ACCOUNT, "COMPLIANT", None),
        ("multi-region-cloudtrail-enabled", "AWS::::Account", ACCOUNT, "COMPLIANT", None),
        ("cloud-trail-log-file-validation-enabled", "AWS::CloudTrail::Trail", "cms-demo-trail", "COMPLIANT", None),
        ("vpc-flow-logs-enabled", "AWS::EC2::VPC", "vpc-0a1b2c3d4e5f60001", "NON_COMPLIANT", "VPC flow logs are off."),
        ("cw-loggroup-retention-period-check", "AWS::Logs::LogGroup", "/cms-demo/app", "COMPLIANT", None),
        ("ec2-instance-managed-by-systems-manager", "AWS::EC2::Instance", "i-0a1b2c3d4e5f60003", "COMPLIANT", None),
        ("guardduty-enabled-centralized", "AWS::::Account", ACCOUNT, "COMPLIANT", None),
        ("ec2-managedinstance-patch-compliance-status-check", "AWS::SSM::PatchCompliance", "i-0a1b2c3d4e5f60002",
         "NON_COMPLIANT", "2 missing security patches."),
        ("backup-plan-min-frequency-and-min-retention-check", "AWS::Backup::BackupPlan", "cms-demo-daily",
         "COMPLIANT", None),
    ]  # fmt: skip
    return {
        "account_id": ACCOUNT,
        "region": REGION,
        "generated": "2026-11-10T14:00:00Z",
        "description": "SYNTHETIC AWS Config rule evaluations for CMS-DEMO.",
        "findings": [
            {"config_rule_name": r, "resource_type": t, "resource_id": i, "compliance_type": c, "annotation": a}
            for r, t, i, c, a in rows
        ],
    }


def poam_findings() -> list[dict]:
    """POA&M items (poam-generator input) for the weaknesses the assessment found."""
    base = {"source": "Audit", "detection_date": "2026-11-10", "office_org": "CMS-DEMO Operations (synthetic)"}
    items = [
        ("SSH open to the internet on the application security group", "SC-7", "High", "In Progress",
         "Security group sg-0a1b2c3d4e5f60001 allows port 22 from 0.0.0.0/0.", "2026-12-10",
         "Lead Systems Administrator, CMS-DEMO (synthetic)",
         ["2026-11-24: Restrict SSH to the bastion subnet", "2026-12-10: Confirm with restricted-ssh rule"]),
        ("VPC flow logs disabled", "AU-12", "Moderate", "Open",
         "Flow logs are not enabled on the CMS-DEMO VPC.", "2027-01-15", "ISSO, CMS-DEMO (synthetic)",
         ["2026-12-15: Enable flow logs to central logging", "2027-01-15: Add alerting on rejected flows"]),
        ("Password policy below agency minimum", "IA-5", "Moderate", "Open",
         "IAM password policy allows 8-character passwords.", "2027-01-31", "ISSO, CMS-DEMO (synthetic)",
         ["2026-12-31: Set 14-character minimum", "2027-01-31: Verify with iam-password-policy rule"]),
        ("Log bucket has no default encryption", "SC-28", "Moderate", "Open",
         "Bucket cms-demo-logs has no default encryption configuration.", "2027-01-31",
         "Lead Systems Administrator, CMS-DEMO (synthetic)", ["2027-01-15: Enable SSE-KMS on cms-demo-logs"]),
        ("Undeclared S3 bucket in the account", "CM-8", "High", "Open",
         "Bucket cms-demo-export-tmp exists but is not in the SSP inventory.", "2026-12-17",
         "ISSO, CMS-DEMO (synthetic)", ["2026-12-03: Decide: delete or add to the SSP and assess"]),
    ]  # fmt: skip
    out = []
    for name, control, severity, status, desc, due, poc, milestones in items:
        out.append(
            {
                **base,
                "weakness_name": name,
                "weakness_description": desc,
                "security_control": control,
                "severity": {"Moderate": "Medium"}.get(severity, severity),
                "scheduled_completion": due,
                "point_of_contact": poc,
                "resources_required": "Staff time (synthetic estimate)",
                "remediation_plan": milestones[0].split(": ", 1)[1],
                "milestones": milestones,
                "status": status,
                "comments": "SYNTHETIC",
            }
        )
    return out


def render(doc) -> str:
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def build() -> dict[Path, str]:
    return {
        INPUTS / "system.yaml": system_yaml(),
        INPUTS / "terraform.tfstate": render(terraform_state()),
        INPUTS / "aws-config-inventory.json": render(config_inventory(0)),
        INPUTS / "aws-config-inventory-day30.json": render(config_inventory(30)),
        INPUTS / "aws-config-findings.json": render(config_findings()),
        INPUTS / "poam-findings.json": render(poam_findings()),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args(argv)
    files = build()
    if args.check:
        stale = [p for p, t in files.items() if not p.is_file() or p.read_text(encoding="utf-8") != t]
        for p in stale:
            print(f"out of date: {p.relative_to(ROOT)}", file=sys.stderr)
        return 1 if stale else 0
    for path, text in files.items():
        path.write_text(text, encoding="utf-8")
        print(f"wrote {path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
