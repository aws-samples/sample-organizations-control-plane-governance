#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Generate the AWS Organizations control-plane conformance pack from guard-rules/*.guard.

The rule manifest is read from deploy-guard-rules.sh so the pack, the deploy script and the tested
rule files never drift apart. Output: conformance-pack-orgs-control-plane.yaml

Usage: python3 build-conformance-pack.py
"""
import collections, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
RULES = os.path.join(HERE, "guard-rules")
OUT = os.path.join(HERE, "conformance-pack-orgs-control-plane.yaml")

# Pack parameters: rule parameter key -> (CFN parameter name, default, description)
PARAMS = {
    "expectedFeatureSet":  ("ExpectedFeatureSet", "ALL", "Expected AWS Organizations feature set"),
    "managementAccountId": ("ManagementAccountId", "111122223333", "Management account ID"),
    "tagValue":            ("GovernedTagValue", "governed",
                            "Value of the 'purpose' tag that marks accounts governed by the approved-OU rule"),
}
SECTIONS = collections.OrderedDict([
    ("AWS::Organizations::Organization", "Organization - org identity"),
    ("AWS::Organizations::Account", "Account - placement, ownership, identity"),
    ("AWS::Organizations::OrganizationalUnit", "Organizational unit - structure"),
    ("AWS::Organizations::Policy", "Policy - authorization and declarative policies"),
    ("AWS::Organizations::ResourcePolicy", "Resource policy - delegation of Organizations management"),
])
LITERALS = {  # environment-specific values that must be edited in the rule text (Guard 2.x regex is literal)
    "account-email-domain.guard": "corporate email domain (example\\.com placeholder)",
    "bedrock-guardrail-enforcement.guard": "management account ID in the guardrail ARN regex",
    "tagged-account-in-approved-ou.guard": "organization / root / approved OU path regex",
}

def manifest():
    with open(os.path.join(HERE, "deploy-guard-rules.sh"), encoding="utf-8") as f:
        text = f.read()
    body = re.search(r"MANIFEST=\$\(cat <<EOF\n(.*?)\nEOF", text, re.S).group(1)
    for line in body.splitlines():
        if line.strip():
            suffix, gfile, rtype, params = line.split("|", 3)
            yield suffix, gfile, rtype, params

def logical_id(suffix):
    return "".join(p.capitalize() for p in re.split(r"[-_]", suffix))

def policy_text(path):
    """Rule text without comment-only lines (keeps the pack small); the .guard file stays the source."""
    with open(path, encoding="utf-8") as f:
        lines = [l.rstrip() for l in f.read().splitlines()]
    kept = [l for l in lines if l.strip() and not l.lstrip().startswith("#")]
    return "\n".join(kept) + "\n"

def description(path):
    """Return the text of the "# Description:" comment line in a Guard rule file."""
    with open(path, encoding="utf-8") as f:
        for l in f.read().splitlines():
            if l.startswith("# Description:"):
                return l.split(":", 1)[1].strip()
    sys.exit(f"{path}: missing '# Description:' line")

rules = list(manifest())
by_type = collections.OrderedDict((t, []) for t in SECTIONS)
for r in rules:
    by_type[r[2]].append(r)

out = []
w = out.append
w("#" * 82)
w("# Conformance Pack: AWS Organizations Control-Plane Security & Governance")
w("#")
w("# Description: Guard (guard-2.x.x) custom policy rules that evaluate the AWS Config")
w("# configuration items for the AWS Organizations control plane: the organization, accounts,")
w("# OUs, every in-scope policy type (SCP, RCP, EC2, S3, GuardDuty, Bedrock, AI opt-out, Backup,")
w("# Upgrade rollout, Tag, Chat applications, Security Hub, Inspector) and the org resource policy.")
w("#")
w("# DEPLOY AS AN ACCOUNT-LEVEL PACK IN THE MANAGEMENT ACCOUNT, us-east-1 - the only place the")
w("# AWS::Organizations::* configuration items are recorded. All rules are change-triggered")
w("# (Guard rules cannot be periodic).")
w("#")
w(f"# Total Rules: {len(rules)}")
w("#")
w("# Coverage:")
for t, rs in by_type.items():
    w(f"# - {t.split('::')[-1]}: {len(rs)} rules")
w("#")
w("# IMPORTANT: Rules with Configurable Parameters (single values only - pack parameters are")
w("# strings, so list parameters are not used)")
n = 0
for suffix, gfile, rtype, params in rules:
    p = json.loads(params)
    if p:
        n += 1
        w(f"# {n}. {suffix}")
        for k in p:
            w(f"#    - {k}: {PARAMS[k][0]}")
w("#")
w("# IMPORTANT: Environment-specific literals to edit per customer (Guard 2.x regex must be literal)")
for i, (f, what) in enumerate(LITERALS.items(), 1):
    w(f"# {i}. {f[:-6]} - {what}")
w("#")
w("# Source of truth: guard-rules/*.guard (tested locally and live). Regenerate with")
w("#   python3 build-conformance-pack.py")
w("#" * 82)
w("")
w("Parameters:")
for k, (name, default, desc) in PARAMS.items():
    w(f"  {name}:")
    w("    Type: String")
    w(f'    Default: "{default}"')
    w(f'    Description: "{desc}"')
w("")
w("Resources:")
for t, rs in by_type.items():
    w("")
    w("  # " + "=" * 60)
    w(f"  # {SECTIONS[t]} ({len(rs)} rules)")
    w("  # " + "=" * 60)
    for suffix, gfile, rtype, params in rs:
        path = os.path.join(RULES, gfile)
        p = json.loads(params)
        w("")
        w(f"  {logical_id(suffix)}:")
        w("    Type: AWS::Config::ConfigRule")
        w("    Properties:")
        w(f"      ConfigRuleName: {suffix}")
        w(f"      Description: {json.dumps(description(path)[:256])}")
        w("      Scope:")
        w("        ComplianceResourceTypes:")
        w(f"          - {rtype}")
        if p:
            w("      InputParameters:")
            for k in p:
                w(f"        {k}:")
                w(f"          Ref: {PARAMS[k][0]}")
        w("      Source:")
        w("        Owner: CUSTOM_POLICY")
        w("        SourceDetails:")
        w("          - EventSource: aws.config")
        w("            MessageType: ConfigurationItemChangeNotification")
        w("          - EventSource: aws.config")
        w("            MessageType: OversizedConfigurationItemChangeNotification")
        w("        CustomPolicyDetails:")
        w("          PolicyRuntime: guard-2.x.x")
        w("          EnableDebugLogDelivery: false")
        w("          PolicyText: |")
        for line in policy_text(path).splitlines():
            w(("            " + line) if line else "")
with open(OUT, "w", encoding="utf-8") as f:
    f.write("\n".join(out) + "\n")
print(f"wrote {OUT}  rules={len(rules)}  bytes={os.path.getsize(OUT)}")
