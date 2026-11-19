# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""AWS Config custom Lambda rule: required organization policies are attached to every OU in scope.

A required policy counts as attached to an OU when it is attached to the OU itself or to any ancestor
(a parent OU or the organization root), because organization policies are inherited down the tree.
Works for every policy type: SCPs, RCPs, and all declarative policy types.

This check needs the OU tree and the attachments of several resources at once, which is why it is a
Lambda rule rather than a Guard rule (a Guard rule evaluates one configuration item at a time).

Deploy in the AWS Organizations MANAGEMENT account, us-east-1. Rule parameters (all strings):
  requiredPolicyIds  comma-separated policy IDs, for example "p-aaaa1111,p-bbbb2222"   (required)
  targetOuIds        comma-separated OU IDs; each listed OU AND every OU below it is evaluated.
                     Omit or leave empty to evaluate every OU in the organization. IDs that don't
                     exist are logged; if none exist, the evaluation fails with an error.
  excludedOuIds      comma-separated OU IDs to skip (optional; unknown IDs are logged)

Triggers: configuration changes to AWS::Organizations::OrganizationalUnit and
AWS::Organizations::Policy (attach, detach, and OU moves change these), plus a periodic run.
Each invocation evaluates all OUs in scope and reports one result per OU.
"""
import json
import os
import time

import boto3
from botocore.config import Config as BotoConfig

RESOURCE_TYPE = "AWS::Organizations::OrganizationalUnit"
_BOTO = BotoConfig(retries={"max_attempts": 10, "mode": "adaptive"})


def _csv(value):
    return [v.strip() for v in (value or "").split(",") if v.strip()]


def _error_code(exc):
    """Error code of a botocore ClientError (None for other exceptions)."""
    return (getattr(exc, "response", None) or {}).get("Error", {}).get("Code")


def _paginate(client, op, key, **kwargs):
    for page in client.get_paginator(op).paginate(**kwargs):
        yield from page[key]


class OrgView:
    """Read-only view of the organization tree and policy attachments, with per-invocation caching."""

    def __init__(self, org):
        self.org = org
        self.root_id = org.list_roots()["Roots"][0]["Id"]
        self.parent = {}           # ou_id -> parent id (OU or root)
        self.children = {}         # parent id -> [ou_id]
        self.names = {}            # ou_id -> name
        self._attached = {}        # (target_id, policy_type) -> set(policy_id)
        self._load_tree(self.root_id)

    def _load_tree(self, parent_id):
        queue = [parent_id]
        while queue:
            pid = queue.pop()
            kids = list(_paginate(self.org, "list_organizational_units_for_parent",
                                  "OrganizationalUnits", ParentId=pid))
            self.children[pid] = [k["Id"] for k in kids]
            for k in kids:
                self.parent[k["Id"]] = pid
                self.names[k["Id"]] = k.get("Name", "")
                queue.append(k["Id"])

    def all_ous(self):
        return list(self.parent)

    def subtree(self, ou_id):
        out, queue = [], [ou_id]
        while queue:
            cur = queue.pop()
            out.append(cur)
            queue.extend(self.children.get(cur, []))
        return out

    def chain(self, ou_id):
        """The OU, its ancestors, and the root (inheritance path)."""
        path, cur = [ou_id], ou_id
        while cur in self.parent:
            cur = self.parent[cur]
            path.append(cur)
        return path

    def attached(self, target_id, policy_type):
        key = (target_id, policy_type)
        if key not in self._attached:
            self._attached[key] = {p["Id"] for p in _paginate(
                self.org, "list_policies_for_target", "Policies", TargetId=target_id, Filter=policy_type)}
        return self._attached[key]


def evaluate(org, params, warnings=None):
    """Return [(ou_id, compliance, annotation)] for every OU in scope.

    OU IDs in targetOuIds or excludedOuIds that don't exist are reported in ``warnings`` (and in the
    function log). If none of the targetOuIds exist, a ValueError is raised so the misconfiguration
    shows up as a failed rule evaluation instead of silently evaluating nothing. A required policy
    that no longer exists (deleted) makes every OU in scope NON_COMPLIANT.
    """
    warnings = warnings if warnings is not None else []
    required = _csv(params.get("requiredPolicyIds"))
    if not required:
        raise ValueError("Rule parameter requiredPolicyIds is required (comma-separated policy IDs)")
    view = OrgView(org)

    policies = {}  # policy_id -> (type, name); type is None for a deleted or unknown policy
    for pid in required:
        try:
            summary = org.describe_policy(PolicyId=pid)["Policy"]["PolicySummary"]
        except Exception as exc:  # botocore ClientError; other errors (for example AccessDenied) re-raise
            if _error_code(exc) != "PolicyNotFoundException":
                raise
            warnings.append(f"Required policy {pid} not found (deleted?); every OU in scope is NON_COMPLIANT")
            policies[pid] = (None, "deleted or not found")
            continue
        policies[pid] = (summary["Type"], summary["Name"])

    targets = _csv(params.get("targetOuIds"))
    unknown_targets = [ou for ou in targets if ou not in view.parent]
    if unknown_targets:
        warnings.append("targetOuIds not found in the organization: " + ", ".join(unknown_targets))
        if len(unknown_targets) == len(targets):
            raise ValueError("None of the targetOuIds exist in the organization: " + ", ".join(targets))
    in_scope = []
    for ou in (targets or view.all_ous()):
        if ou in unknown_targets:
            continue
        for o in (view.subtree(ou) if targets else [ou]):
            if o not in in_scope:
                in_scope.append(o)
    excluded = set(_csv(params.get("excludedOuIds")))
    unknown_excluded = sorted(excluded - set(view.parent))
    if unknown_excluded:
        warnings.append("excludedOuIds not found in the organization: " + ", ".join(unknown_excluded))

    results = []
    for ou in in_scope:
        if ou in excluded:
            continue
        chain = view.chain(ou)
        missing = [pid for pid, (ptype, _) in policies.items()
                   if ptype is None or not any(pid in view.attached(t, ptype) for t in chain)]
        if missing:
            detail = ", ".join(f"{policies[p][1]} ({p}, {policies[p][0] or 'UNKNOWN_TYPE'})" for p in missing)
            note = f"Missing {len(missing)} of {len(policies)} required policies: {detail}"
            results.append((ou, "NON_COMPLIANT", note[:256]))
        else:
            results.append((ou, "COMPLIANT",
                            f"All {len(policies)} required policies attached to the OU or inherited"[:256]))
    return results


def lambda_handler(event, context):
    invoking = json.loads(event["invokingEvent"])
    params = json.loads(event.get("ruleParameters") or "{}")
    timestamp = invoking.get("notificationCreationTime") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    org = boto3.client("organizations", region_name=os.environ.get("AWS_REGION", "us-east-1"), config=_BOTO)
    warnings = []
    results = evaluate(org, params, warnings)
    for w in warnings:
        print(f"WARNING: {w}")

    evaluations = [{"ComplianceResourceType": RESOURCE_TYPE, "ComplianceResourceId": ou,
                    "ComplianceType": compliance, "Annotation": note, "OrderingTimestamp": timestamp}
                   for ou, compliance, note in results]
    config = boto3.client("config", config=_BOTO)
    for i in range(0, len(evaluations), 100):  # PutEvaluations accepts up to 100 per call
        config.put_evaluations(Evaluations=evaluations[i:i + 100], ResultToken=event["resultToken"],
                               TestMode=event["resultToken"] == "TESTMODE")
    print(json.dumps({"evaluated": len(results),
                      "non_compliant": sum(r[1] == "NON_COMPLIANT" for r in results),
                      "warnings": warnings}))
    return {"evaluated": len(results)}
