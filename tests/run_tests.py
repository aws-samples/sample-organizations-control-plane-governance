#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Local test suite for guard-rules/*.guard using synthetic AWS Config configuration items.

Each case builds a CI, runs `cfn-guard validate`, and maps the result the way AWS Config does:
any FAIL -> NON_COMPLIANT, all SKIP -> NOT_APPLICABLE, otherwise COMPLIANT.

Requires the cfn-guard CLI on PATH. IMPORTANT: AWS Config runs Guard 2.x; the CLI you install may
be 3.x. Passing these tests is necessary but not sufficient - always confirm rules live in AWS
Config with known compliant and non-compliant resources (see README).

Usage: python3 tests/run_tests.py [-v]
"""
import copy, json, os, re, shutil, sys, tempfile
# subprocess runs only the cfn-guard CLI, by absolute path, with a fixed argument list and no shell.
import subprocess  # nosec B404

HERE = os.path.dirname(os.path.abspath(__file__))
RULES = os.path.join(HERE, "..", "guard-rules")
MGMT, MEMBER, ORG, ROOT = "111122223333", "444455556666", "o-exampleorgid", "r-exmp"
PARAMS = {"org-feature-set-all.guard": {"expectedFeatureSet": "ALL"},
          "org-expected-management-account.guard": {"managementAccountId": MGMT},
          "account-not-at-root.guard": {"managementAccountId": MGMT},
          "tagged-account-in-approved-ou.guard": {"tagValue": "governed"}}

# ---------- synthetic configuration items ----------
def ci(rtype, cfg, tags=None, rid="example"):
    return {"resourceType": rtype, "resourceId": rid, "accountId": MGMT, "awsRegion": "us-east-1",
            "configuration": cfg, "tags": tags or {}, "supplementaryConfiguration": {}}

ORG_CI = ci("AWS::Organizations::Organization", {"Id": ORG, "RootId": ROOT, "FeatureSet": "ALL",
            "ManagementAccountId": MGMT})
ACCT = ci("AWS::Organizations::Account", {"AccountId": MEMBER, "AccountName": "Workload",
          "Email": "workload@example.com", "Status": "ACTIVE", "State": "ACTIVE",
          "ParentIds": ["ou-exmp-nested"],
          "Paths": [f"{ORG}/{ROOT}/ou-exmp-approved/ou-exmp-nested/{MEMBER}/"]}, tags={"purpose": "governed"})
MGMT_ACCT = ci("AWS::Organizations::Account", {"AccountId": MGMT, "AccountName": "Management",
               "Email": "management@example.com", "ParentIds": [ROOT], "Paths": [f"{ORG}/{ROOT}/{MGMT}/"]})
OU = ci("AWS::Organizations::OrganizationalUnit", {"Id": "ou-exmp-nested", "Name": "Nested",
        "ParentId": "ou-exmp-approved", "Path": f"{ORG}/{ROOT}/ou-exmp-approved/ou-exmp-nested/"})
RP = ci("AWS::Organizations::ResourcePolicy", {"Id": "rp-example", "Content": "REDACTED"})

def pol(ptype, content, targets=("ou-exmp-approved",), managed=False):
    return ci("AWS::Organizations::Policy", {"Type": ptype, "Content": content, "TargetIds": list(targets),
              "AwsManaged": managed, "Description": "REDACTED"})

SCP = pol("SERVICE_CONTROL_POLICY", {"Version": "2012-10-17", "Statement": [
    {"Sid": "RequireTag", "Effect": "Deny", "Action": ["ec2:RunInstances"], "Resource": "*",
     "Condition": {"Null": {"aws:RequestTag/env": "true"}}}]})
FULL = pol("SERVICE_CONTROL_POLICY", {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Action": "*", "Resource": "*"}]}, targets=(ROOT,), managed=True)
RCP = pol("RESOURCE_CONTROL_POLICY", {"Version": "2012-10-17", "Statement": [
    {"Effect": "Deny", "Principal": "*", "Action": "secretsmanager:*", "Resource": "*",
     "Condition": {"StringNotEqualsIfExists": {"aws:PrincipalOrgID": ORG},
                   "BoolIfExists": {"aws:PrincipalIsAWSService": "false"}}}]})
S3 = pol("S3_POLICY", {"s3_attributes": {"public_access_block_configuration": {"@@assign": "all"}}})
EC2 = pol("DECLARATIVE_POLICY_EC2", {"ec2_attributes": {"vpc_block_public_access": {"internet_gateway_block": {
    "mode": {"@@assign": "block_ingress"}, "exclusions_allowed": {"@@assign": "enabled"}}}}})
GD = pol("GUARDDUTY_POLICY", {"guardduty": {"enablement": {"us-east-1": {"foundational": {"status": {"@@assign": "enabled"}}}}}})
BED, OPT, BAK = pol("BEDROCK_POLICY", {}), pol("AISERVICES_OPT_OUT_POLICY", {}), pol("BACKUP_POLICY", {})
UPG = pol("UPGRADE_ROLLOUT_POLICY", {"upgrade_rollout": {"default": {"patch_order": {"@@assign": "last"}}}})
TAG, CHAT = pol("TAG_POLICY", {}), pol("CHATBOT_POLICY", {"chatbot": {"default": {"client": {"@@assign": "disabled"}}}})
SH, INSP = pol("SECURITYHUB_POLICY", {}, targets=(ROOT,)), pol("INSPECTOR_POLICY", {}, targets=(ROOT,))

def mut(base, fn):
    d = copy.deepcopy(base); fn(d); return d
def cfg(**kv):
    return lambda d: d["configuration"].update(kv)
def content(base, c):
    return mut(base, lambda d: d["configuration"].__setitem__("Content", c))
def stmts(base, *s):
    return content(base, {"Version": "2012-10-17", "Statement": list(s)})
def ec2(attrs):
    return content(EC2, {"ec2_attributes": attrs})

ARN = f"arn:aws:bedrock:us-east-1:{MGMT}:guardrail/exampleid1:1"
def bed(arn=ARN, **kw):
    c = {"identifier": {"@@assign": arn}}
    g = {k: {"@@assign": kw[k]} for k in ("system", "messages") if k in kw}
    if g: c["selective_content_guarding"] = g
    if "excluded" in kw:
        c["model_enforcement"] = {"included_models": {"@@assign": ["ALL"]}, "excluded_models": {"@@assign": kw["excluded"]}}
    return content(BED, {"bedrock": {"guardrail_inference": {"us-east-1": {"config_1": c}}}})
def opt(services):
    return content(OPT, {"services": {k: {"opt_out_policy": {"@@assign": v}} for k, v in services.items()}})
def bak(**over):
    r = {"schedule_expression": {"@@assign": "cron(0 5 ? * * *)"}, "lifecycle": {"delete_after_days": {"@@assign": "35"}},
         "copy_actions": {"arn:aws:backup:us-west-2:$account:backup-vault:Default": {
             "target_backup_vault_arn": {"@@assign": "arn:aws:backup:us-west-2:$account:backup-vault:Default"}}}}
    for k, v in over.items():
        if v is None: r.pop(k, None)
        else: r[k] = v
    return content(BAK, {"plans": {"P1": {"regions": {"@@assign": ["us-east-1"]}, "rules": {"R1": r}}}})
def sh(enable=("ALL_SUPPORTED",), disable=(), op="@@append", lock="@@all", targets=(ROOT,)):
    d = content(SH, {"securityhub": {
        "enable_in_regions": {op: list(enable), "@@operators_allowed_for_child_policies": [lock]},
        "disable_in_regions": {op: list(disable), "@@operators_allowed_for_child_policies": [lock]}}})
    d["configuration"]["TargetIds"] = list(targets); return d
def scan(enable=("ALL_SUPPORTED",), disable=(), lock="@@all"):
    return {"enable_in_regions": {"@@append": list(enable), "@@operators_allowed_for_child_policies": [lock]},
            "disable_in_regions": {"@@append": list(disable), "@@operators_allowed_for_child_policies": [lock]}}
def insp(**over):
    en = {"ec2_scanning": scan(), "ecr_scanning": scan(), "lambda_standard_scanning": scan()}
    for k, v in over.items():
        if v is None: en.pop(k)
        else: en[k] = v
    return content(INSP, {"inspector": {"enablement": en}})
def tagp(tags):
    return content(TAG, {"tags": tags})
def chat(c):
    return content(CHAT, {"chatbot": c})
def upg(c):
    return content(UPG, {"upgrade_rollout": c})
APPROVED_PATH = f"{ORG}/{ROOT}/ou-exmp-approved/{MEMBER}/"

C, N, NA = "COMPLIANT", "NON_COMPLIANT", "NOT_APPLICABLE"
CASES = [
 # Organization
 ("feature set ALL", ORG_CI, "org-feature-set-all.guard", C),
 ("feature set CONSOLIDATED_BILLING", mut(ORG_CI, cfg(FeatureSet="CONSOLIDATED_BILLING")), "org-feature-set-all.guard", N),
 ("expected management account", ORG_CI, "org-expected-management-account.guard", C),
 ("other management account", mut(ORG_CI, cfg(ManagementAccountId="999999999999")), "org-expected-management-account.guard", N),
 # Account
 ("member under OU", ACCT, "account-not-at-root.guard", C),
 ("member at root", mut(ACCT, cfg(ParentIds=[ROOT])), "account-not-at-root.guard", N),
 ("management account at root (exempt)", MGMT_ACCT, "account-not-at-root.guard", NA),
 ("governed account under approved subtree", ACCT, "tagged-account-in-approved-ou.guard", C),
 ("governed account directly in approved OU", mut(ACCT, cfg(Paths=[APPROVED_PATH])), "tagged-account-in-approved-ou.guard", C),
 ("governed account at root", mut(ACCT, cfg(Paths=[f"{ORG}/{ROOT}/{MEMBER}/"])), "tagged-account-in-approved-ou.guard", N),
 ("governed account in other OU", mut(ACCT, cfg(Paths=[f"{ORG}/{ROOT}/ou-exmp-other/{MEMBER}/"])), "tagged-account-in-approved-ou.guard", N),
 ("governed account in lookalike OU", mut(ACCT, cfg(Paths=[f"{ORG}/{ROOT}/ou-exmp-approvedx/{MEMBER}/"])), "tagged-account-in-approved-ou.guard", N),
 ("untagged account (out of scope)", MGMT_ACCT, "tagged-account-in-approved-ou.guard", NA),
 ("owner tag present", mut(ACCT, lambda d: d["tags"].update(owner="team-a")), "account-required-owner-tag.guard", C),
 ("owner tag missing", ACCT, "account-required-owner-tag.guard", N),
 ("owner tag empty", mut(ACCT, lambda d: d["tags"].update(owner="")), "account-required-owner-tag.guard", N),
 ("email on corporate domain", ACCT, "account-email-domain.guard", C),
 ("email UPPERCASE domain", mut(ACCT, cfg(Email="X@EXAMPLE.COM")), "account-email-domain.guard", C),
 ("email personal domain", mut(ACCT, cfg(Email="someone@gmail.com")), "account-email-domain.guard", N),
 ("email lookalike domain", mut(ACCT, cfg(Email="x@example.com.evil.io")), "account-email-domain.guard", N),
 # OU
 ("OU depth 2", OU, "ou-max-depth.guard", C),
 ("OU depth 3 (limit)", mut(OU, cfg(Path=f"{ORG}/{ROOT}/ou-exmp-a1/ou-exmp-b2/ou-exmp-c3/")), "ou-max-depth.guard", C),
 ("OU depth 4", mut(OU, cfg(Path=f"{ORG}/{ROOT}/ou-exmp-a1/ou-exmp-b2/ou-exmp-c3/ou-exmp-d4/")), "ou-max-depth.guard", N),
 # SCP / RCP / hygiene
 ("SCP deny-only", SCP, "scp-no-allow-star.guard", C),
 ("SCP Allow * (string)", stmts(SCP, {"Effect": "Allow", "Action": "*", "Resource": "*"}), "scp-no-allow-star.guard", N),
 ("SCP Allow * (in list)", stmts(SCP, {"Effect": "Allow", "Action": ["s3:GetObject", "*"], "Resource": "*"}), "scp-no-allow-star.guard", N),
 ("SCP Allow scoped", stmts(SCP, {"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"}), "scp-no-allow-star.guard", C),
 ("AWS-managed FullAWSAccess (exempt)", FULL, "scp-no-allow-star.guard", NA),
 ("custom SCP on OU", SCP, "scp-custom-not-on-root.guard", C),
 ("custom SCP on root", mut(SCP, cfg(TargetIds=["ou-exmp-approved", ROOT])), "scp-custom-not-on-root.guard", N),
 ("RCP OrgID under one of two operators", RCP, "rcp-deny-uses-org-condition.guard", C),
 ("RCP Deny without Condition", stmts(RCP, {"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "*"}), "rcp-deny-uses-org-condition.guard", N),
 ("RCP Deny keyed on PrincipalAccount", stmts(RCP, {"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "*",
   "Condition": {"StringEquals": {"aws:PrincipalAccount": MEMBER}}}), "rcp-deny-uses-org-condition.guard", N),
 ("custom policy attached", SCP, "policy-attached.guard", C),
 ("custom policy unattached", mut(SCP, cfg(TargetIds=[])), "policy-attached.guard", N),
 ("AWS-managed unattached (exempt)", mut(FULL, cfg(TargetIds=[])), "policy-attached.guard", NA),
 ("resource policy not reviewed", RP, "org-resource-policy-review.guard", N),
 ("resource policy reviewed=true", mut(RP, lambda d: d["tags"].update(reviewed="true")), "org-resource-policy-review.guard", C),
 ("resource policy reviewed=false", mut(RP, lambda d: d["tags"].update(reviewed="false")), "org-resource-policy-review.guard", N),
 # S3 / EC2 / GuardDuty
 ("S3 BPA all", S3, "s3-policy-bpa-all.guard", C),
 ("S3 BPA none", content(S3, {"s3_attributes": {"public_access_block_configuration": {"@@assign": "none"}}}), "s3-policy-bpa-all.guard", N),
 ("EC2 VPC BPA block_ingress", EC2, "ec2-declarative-secure-values.guard", C),
 ("EC2 VPC BPA off", ec2({"vpc_block_public_access": {"internet_gateway_block": {"mode": {"@@assign": "off"}}}}), "ec2-declarative-secure-values.guard", N),
 ("EC2 image BPA unblocked", ec2({"image_block_public_access": {"state": {"@@assign": "unblocked"}}}), "ec2-declarative-secure-values.guard", N),
 ("EC2 snapshot BPA unblocked", ec2({"snapshot_block_public_access": {"state": {"@@assign": "unblocked"}}}), "ec2-declarative-secure-values.guard", N),
 ("EC2 serial console enabled", ec2({"serial_console_access": {"status": {"@@assign": "enabled"}}}), "ec2-declarative-secure-values.guard", N),
 ("EC2 IMDS optional", ec2({"instance_metadata_defaults": {"http_tokens": {"@@assign": "optional"}}}), "ec2-declarative-secure-values.guard", N),
 ("EC2 IMDS required", ec2({"instance_metadata_defaults": {"http_tokens": {"@@assign": "required"}}}), "ec2-declarative-secure-values.guard", C),
 ("EC2 allowed images disabled", ec2({"allowed_images_settings": {"state": {"@@assign": "disabled"}}}), "ec2-declarative-secure-values.guard", N),
 ("EC2 VPC encryption unmanaged", ec2({"vpc_encryption_control": {"mode": {"@@assign": "unmanaged"}}}), "ec2-declarative-secure-values.guard", N),
 ("EC2 multi-attribute, one bad", ec2({"serial_console_access": {"status": {"@@assign": "disabled"}},
   "instance_metadata_defaults": {"http_tokens": {"@@assign": "optional"}}}), "ec2-declarative-secure-values.guard", N),
 ("EC2 exception_message only", ec2({"exception_message": {"@@assign": "x"}}), "ec2-declarative-secure-values.guard", C),
 ("GuardDuty region enabled", GD, "guardduty-foundational-enabled.guard", C),
 ("GuardDuty Region block disables", content(GD, {"guardduty": {"enablement": {"default": {"foundational": {"status": {"@@assign": "enabled"}}},
   "us-west-2": {"foundational": {"status": {"@@assign": "disabled"}}}}}}), "guardduty-foundational-enabled.guard", N),
 # Bedrock / AI opt-out
 ("Bedrock comprehensive", bed(system="comprehensive", messages="comprehensive"), "bedrock-guardrail-enforcement.guard", C),
 ("Bedrock guarding omitted (default)", bed(), "bedrock-guardrail-enforcement.guard", C),
 ("Bedrock system selective", bed(system="selective", messages="comprehensive"), "bedrock-guardrail-enforcement.guard", N),
 ("Bedrock messages selective", bed(system="comprehensive", messages="selective"), "bedrock-guardrail-enforcement.guard", N),
 ("Bedrock DRAFT version", bed(arn=f"arn:aws:bedrock:us-east-1:{MGMT}:guardrail/abc123:DRAFT"), "bedrock-guardrail-enforcement.guard", N),
 ("Bedrock unversioned guardrail", bed(arn=f"arn:aws:bedrock:us-east-1:{MGMT}:guardrail/abc123"), "bedrock-guardrail-enforcement.guard", N),
 ("Bedrock guardrail in AWS GovCloud (US)", bed(arn=f"arn:aws-us-gov:bedrock:us-gov-west-1:{MGMT}:guardrail/abc123:1"), "bedrock-guardrail-enforcement.guard", C),
 ("Bedrock guardrail in unknown partition", bed(arn=f"arn:aws-cn:bedrock:cn-north-1:{MGMT}:guardrail/abc123:1"), "bedrock-guardrail-enforcement.guard", N),
 ("Bedrock guardrail in other account", bed(arn="arn:aws:bedrock:us-east-1:999999999999:guardrail/abc123:1"), "bedrock-guardrail-enforcement.guard", N),
 ("Bedrock excludes a model", bed(excluded=["cohere.embed-english-v3"]), "bedrock-guardrail-enforcement.guard", N),
 ("Bedrock empty exclusions", bed(excluded=[]), "bedrock-guardrail-enforcement.guard", C),
 ("AI opt-out default + all optOut", opt({"default": "optOut", "lex": "optOut"}), "ai-optout-all-services.guard", C),
 ("AI opt-out without default", opt({"lex": "optOut"}), "ai-optout-all-services.guard", N),
 ("AI opt-out with one optIn", opt({"default": "optOut", "lex": "optIn"}), "ai-optout-all-services.guard", N),
 # Backup / upgrade / tag / chat
 ("Backup compliant", bak(), "backup-plan-minimums.guard", C),
 ("Backup retention 100", bak(lifecycle={"delete_after_days": {"@@assign": "100"}}), "backup-plan-minimums.guard", C),
 ("Backup retention 34", bak(lifecycle={"delete_after_days": {"@@assign": "34"}}), "backup-plan-minimums.guard", N),
 ("Backup retention 7", bak(lifecycle={"delete_after_days": {"@@assign": "7"}}), "backup-plan-minimums.guard", N),
 ("Backup no lifecycle (kept forever)", bak(lifecycle=None), "backup-plan-minimums.guard", C),
 ("Backup no schedule", bak(schedule_expression=None), "backup-plan-minimums.guard", N),
 ("Backup empty copy_actions", bak(copy_actions={}), "backup-plan-minimums.guard", N),
 ("Upgrade explicit default", UPG, "upgrade-rollout-safe-order.guard", C),
 ("Upgrade without default", upg({"tags": {"environment": {"tag_values": {"development": {"patch_order": {"@@assign": "first"}}}}}}), "upgrade-rollout-safe-order.guard", N),
 ("Upgrade production first", upg({"default": {"patch_order": {"@@assign": "last"}},
   "tags": {"environment": {"tag_values": {"production": {"patch_order": {"@@assign": "first"}}}}}}), "upgrade-rollout-safe-order.guard", N),
 ("Upgrade production last", upg({"default": {"patch_order": {"@@assign": "second"}},
   "tags": {"environment": {"tag_values": {"production": {"patch_order": {"@@assign": "last"}}}}}}), "upgrade-rollout-safe-order.guard", C),
 ("Tag well formed", tagp({"env": {"tag_key": {"@@assign": "env"}, "tag_value": {"@@assign": ["dev", "prod"]},
   "enforced_for": {"@@assign": ["ec2:instance"]}}}), "tag-policy-well-formed.guard", C),
 ("Tag entry without tag_key", tagp({"a": {"tag_key": {"@@assign": "a"}}, "b": {"tag_value": {"@@assign": ["x"]}}}), "tag-policy-well-formed.guard", N),
 ("Tag enforced without values", tagp({"a": {"tag_key": {"@@assign": "a"}, "enforced_for": {"@@assign": ["ec2:instance"]}}}), "tag-policy-well-formed.guard", N),
 ("Chat disabled by default", CHAT, "chat-apps-restricted.guard", C),
 ("Chat enabled by default", chat({"default": {"client": {"@@assign": "enabled"}}}), "chat-apps-restricted.guard", N),
 ("Chat Slack without allowlist", chat({"default": {"client": {"@@assign": "disabled"}},
   "platforms": {"slack": {"client": {"@@assign": "enabled"}}}}), "chat-apps-restricted.guard", N),
 ("Chat Slack with allowlist", chat({"default": {"client": {"@@assign": "disabled"}},
   "platforms": {"slack": {"client": {"@@assign": "enabled"}, "workspaces": {"@@assign": ["T0EXAMPLE"]}}}}), "chat-apps-restricted.guard", C),
 ("Chat Slack allows channel_role", chat({"default": {"client": {"@@assign": "disabled"}},
   "platforms": {"slack": {"client": {"@@assign": "enabled"}, "workspaces": {"@@assign": ["T0EXAMPLE"]},
   "default": {"supported_role_settings": {"@@assign": ["user_role", "channel_role"]}}}}}), "chat-apps-restricted.guard", N),
 # Security Hub / Inspector / child lock
 ("Security Hub all Regions", sh(), "securityhub-all-regions.guard", C),
 ("Security Hub @@assign form", sh(op="@@assign"), "securityhub-all-regions.guard", C),
 ("Security Hub disables a Region", sh(disable=["us-west-2"]), "securityhub-all-regions.guard", N),
 ("Security Hub specific Regions only", sh(enable=["us-east-1"]), "securityhub-all-regions.guard", N),
 ("Inspector all scans", insp(), "inspector-required-scans.guard", C),
 ("Inspector missing ECR", insp(ecr_scanning=None), "inspector-required-scans.guard", N),
 ("Inspector Lambda disabled in a Region", insp(lambda_standard_scanning=scan(disable=["eu-west-1"])), "inspector-required-scans.guard", N),
 ("Lock: Security Hub @@all at root", sh(), "security-services-child-locked.guard", N),
 ("Lock: Security Hub @@none at root", sh(lock="@@none"), "security-services-child-locked.guard", C),
 ("Lock: Security Hub not at root", sh(targets=("ou-exmp-approved",)), "security-services-child-locked.guard", NA),
 ("Lock: Inspector @@all at root", insp(), "security-services-child-locked.guard", N),
 ("Lock: Inspector @@none at root", insp(ec2_scanning=scan(lock="@@none"), ecr_scanning=scan(lock="@@none"),
   lambda_standard_scanning=scan(lock="@@none")), "security-services-child-locked.guard", C),
]

CFN_GUARD = shutil.which("cfn-guard")  # resolved once to an absolute path

def evaluate(rule, doc):
    with tempfile.TemporaryDirectory() as t:
        d, p = os.path.join(t, "ci.json"), os.path.join(t, "params.json")
        with open(d, "w", encoding="utf-8") as f:
            json.dump(doc, f)
        with open(p, "w", encoding="utf-8") as f:
            json.dump({"CONFIG_RULE_PARAMETERS": PARAMS.get(rule, {})}, f)
        # Fixed argument list: absolute cfn-guard path, a repository rule file, and the temp files written
        # above. No shell is used, so no input is interpreted by a shell.
        cmd = [CFN_GUARD, "validate", "-r", os.path.join(RULES, rule), "-d", d, "-i", p, "--show-summary", "all"]
        out = subprocess.run(cmd, capture_output=True, text=True, check=False)  # nosec B603 # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit, dangerous-subprocess-use-audit
    text = out.stdout + out.stderr
    st = re.findall(r"^\S+\.guard/\S+\s+(PASS|FAIL|SKIP)\s*$", text, re.M)
    if not st:
        return "ERROR", text.strip()[:300]
    return (N if "FAIL" in st else NA if all(s == "SKIP" for s in st) else C), ""

def main():
    verbose = "-v" in sys.argv
    if not CFN_GUARD:
        sys.exit("cfn-guard not found on PATH - see https://docs.aws.amazon.com/cfn-guard/latest/ug/setting-up.html")
    failed = 0
    covered = set()
    for name, doc, rule, expected in CASES:
        got, err = evaluate(rule, doc)
        covered.add(rule)
        ok = got == expected
        failed += not ok
        if verbose or not ok:
            print(f"{'PASS' if ok else 'FAIL'}  {rule:40} {name:42} expected={expected} got={got} {err}")
    missing = sorted(set(os.listdir(RULES)) - covered)
    print(f"\n{len(CASES) - failed}/{len(CASES)} cases passed across {len(covered)} rules")
    if missing:
        print("rules without tests:", ", ".join(missing))
    sys.exit(1 if failed or missing else 0)

if __name__ == "__main__":
    main()
