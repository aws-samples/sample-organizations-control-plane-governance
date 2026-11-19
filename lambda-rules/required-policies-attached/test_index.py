# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Unit tests for index.py with an in-memory fake AWS Organizations client (no AWS calls).

Usage: python3 lambda-rules/required-policies-attached/test_index.py
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import index  # noqa: E402
except ModuleNotFoundError as exc:  # boto3 is only needed at runtime in Lambda
    if exc.name not in ("boto3", "botocore"):
        raise
    import types
    sys.modules["boto3"] = types.ModuleType("boto3")
    botocore = types.ModuleType("botocore"); botocore_config = types.ModuleType("botocore.config")
    botocore_config.Config = lambda **kw: None
    sys.modules["botocore"], sys.modules["botocore.config"] = botocore, botocore_config
    import index  # noqa: E402

#   r-exmp
#   ├── ou-exmp-prod          (SCP p-scp1, S3 p-s3)
#   │   └── ou-exmp-prod-app  (RCP p-rcp1)
#   ├── ou-exmp-dev
#   └── ou-exmp-sandbox
TREE = {"r-exmp": ["ou-exmp-prod", "ou-exmp-dev", "ou-exmp-sandbox"],
        "ou-exmp-prod": ["ou-exmp-prod-app"], "ou-exmp-prod-app": [], "ou-exmp-dev": [], "ou-exmp-sandbox": []}
POLICIES = {"p-root-bedrock": ("BEDROCK_POLICY", "RootBedrockGuardrail"),
            "p-scp1": ("SERVICE_CONTROL_POLICY", "DenyLeaveOrg"),
            "p-rcp1": ("RESOURCE_CONTROL_POLICY", "DataPerimeter"),
            "p-s3": ("S3_POLICY", "S3BlockPublicAccess")}
ATTACH = {"r-exmp": {"p-root-bedrock"}, "ou-exmp-prod": {"p-scp1", "p-s3"}, "ou-exmp-prod-app": {"p-rcp1"}}


class _ClientError(Exception):
    """Mimics botocore ClientError: carries the error code in .response."""
    def __init__(self, code): super().__init__(code); self.response = {"Error": {"Code": code}}


class _Paginator:
    def __init__(self, fn): self.fn = fn
    def paginate(self, **kw): yield self.fn(**kw)


class FakeOrg:
    def __init__(self, attach=None): self.attach = attach if attach is not None else ATTACH; self.calls = 0
    def list_roots(self): return {"Roots": [{"Id": "r-exmp"}]}
    def describe_policy(self, PolicyId):
        if PolicyId == "p-denied":
            raise _ClientError("AccessDeniedException")
        if PolicyId not in POLICIES:
            raise _ClientError("PolicyNotFoundException")
        t, n = POLICIES[PolicyId]
        return {"Policy": {"PolicySummary": {"Id": PolicyId, "Type": t, "Name": n}}}
    def get_paginator(self, op):
        def ous(ParentId):
            return {"OrganizationalUnits": [{"Id": o, "Name": o.split("-", 2)[-1]} for o in TREE[ParentId]]}
        def pols(TargetId, Filter):
            self.calls += 1
            return {"Policies": [{"Id": p} for p in self.attach.get(TargetId, set()) if POLICIES[p][0] == Filter]}
        return _Paginator({"list_organizational_units_for_parent": ous, "list_policies_for_target": pols}[op])


def run(params, attach=None):
    return {ou: (c, n) for ou, c, n in index.evaluate(FakeOrg(attach), params)}


class RequiredPoliciesAttached(unittest.TestCase):
    def test_inherited_from_root_counts_for_every_ou(self):
        r = run({"requiredPolicyIds": "p-root-bedrock"})
        self.assertEqual({c for c, _ in r.values()}, {"COMPLIANT"})
        self.assertEqual(len(r), 4)  # prod, prod-app, dev, sandbox

    def test_direct_and_inherited_from_parent_ou(self):
        r = run({"requiredPolicyIds": "p-scp1,p-s3"})
        self.assertEqual(r["ou-exmp-prod"][0], "COMPLIANT")       # attached directly
        self.assertEqual(r["ou-exmp-prod-app"][0], "COMPLIANT")   # inherited from parent OU
        self.assertEqual(r["ou-exmp-dev"][0], "NON_COMPLIANT")
        self.assertIn("DenyLeaveOrg (p-scp1, SERVICE_CONTROL_POLICY)", r["ou-exmp-dev"][1])
        self.assertIn("Missing 2 of 2", r["ou-exmp-dev"][1])

    def test_mixed_policy_types(self):
        r = run({"requiredPolicyIds": "p-root-bedrock,p-scp1,p-rcp1"})
        self.assertEqual(r["ou-exmp-prod-app"][0], "COMPLIANT")
        self.assertEqual(r["ou-exmp-prod"][0], "NON_COMPLIANT")   # RCP only on the child OU, not inherited upward
        self.assertIn("DataPerimeter", r["ou-exmp-prod"][1])

    def test_target_ous_include_descendants(self):
        r = run({"requiredPolicyIds": "p-scp1", "targetOuIds": "ou-exmp-prod"})
        self.assertEqual(set(r), {"ou-exmp-prod", "ou-exmp-prod-app"})

    def test_excluded_ous_are_skipped(self):
        r = run({"requiredPolicyIds": "p-scp1", "excludedOuIds": "ou-exmp-sandbox, ou-exmp-dev"})
        self.assertNotIn("ou-exmp-sandbox", r); self.assertNotIn("ou-exmp-dev", r)

    def test_detached_policy_becomes_non_compliant(self):
        detached = {k: set(v) for k, v in ATTACH.items()}; detached["ou-exmp-prod"].discard("p-s3")
        r = run({"requiredPolicyIds": "p-s3", "targetOuIds": "ou-exmp-prod"}, attach=detached)
        self.assertEqual({c for c, _ in r.values()}, {"NON_COMPLIANT"})

    def test_all_target_ous_unknown_raises(self):
        with self.assertRaises(ValueError):
            index.evaluate(FakeOrg(), {"requiredPolicyIds": "p-scp1", "targetOuIds": "ou-exmp-gone"})

    def test_some_target_ous_unknown_are_reported(self):
        warnings = []
        r = {ou: c for ou, c, _ in index.evaluate(
            FakeOrg(), {"requiredPolicyIds": "p-scp1", "targetOuIds": "ou-exmp-gone,ou-exmp-dev"}, warnings)}
        self.assertEqual(set(r), {"ou-exmp-dev"})                 # known OU still evaluated
        self.assertEqual(len(warnings), 1); self.assertIn("ou-exmp-gone", warnings[0])

    def test_unknown_excluded_ou_is_reported(self):
        warnings = []
        index.evaluate(FakeOrg(), {"requiredPolicyIds": "p-scp1", "excludedOuIds": "ou-exmp-typo"}, warnings)
        self.assertEqual(len(warnings), 1); self.assertIn("ou-exmp-typo", warnings[0])

    def test_no_warnings_for_valid_parameters(self):
        warnings = []
        index.evaluate(FakeOrg(), {"requiredPolicyIds": "p-scp1", "targetOuIds": "ou-exmp-prod",
                                   "excludedOuIds": "ou-exmp-prod-app"}, warnings)
        self.assertEqual(warnings, [])

    def test_deleted_policy_makes_every_ou_non_compliant(self):
        warnings = []
        r = {ou: (c, n) for ou, c, n in index.evaluate(
            FakeOrg(), {"requiredPolicyIds": "p-gone"}, warnings)}
        self.assertEqual(len(r), 4)
        self.assertEqual({c for c, _ in r.values()}, {"NON_COMPLIANT"})
        self.assertIn("p-gone", r["ou-exmp-dev"][1]); self.assertIn("deleted or not found", r["ou-exmp-dev"][1])
        self.assertEqual(len(warnings), 1); self.assertIn("p-gone", warnings[0])

    def test_deleted_and_present_policy(self):
        r = run({"requiredPolicyIds": "p-root-bedrock,p-gone"})
        self.assertEqual({c for c, _ in r.values()}, {"NON_COMPLIANT"})
        self.assertIn("Missing 1 of 2", r["ou-exmp-prod"][1])     # bedrock is inherited, only p-gone missing

    def test_other_describe_errors_still_raise(self):
        with self.assertRaises(Exception) as ctx:
            index.evaluate(FakeOrg(), {"requiredPolicyIds": "p-denied"})
        self.assertEqual(index._error_code(ctx.exception), "AccessDeniedException")

    def test_missing_parameter_raises(self):
        with self.assertRaises(ValueError):
            index.evaluate(FakeOrg(), {})

    def test_annotation_within_limit(self):
        for _, note in run({"requiredPolicyIds": "p-root-bedrock,p-scp1,p-rcp1,p-s3"}).values():
            self.assertLessEqual(len(note), 256)

    def test_attachment_lookups_are_cached(self):
        org = FakeOrg(); index.evaluate(org, {"requiredPolicyIds": "p-scp1"})
        self.assertLessEqual(org.calls, 5)  # one lookup per target (4 OUs + root) for one policy type


if __name__ == "__main__":
    unittest.main(verbosity=2)
