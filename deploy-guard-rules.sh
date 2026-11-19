#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
# Deploy the AWS::Organizations::* Guard (guard-2.x.x) custom policy rules in guard-rules/.
# Run in the MANAGEMENT account, us-east-1 (the only place Organizations CIs are recorded).
# Create-or-update; safe to re-run. Rules are change-triggered (Guard rules cannot be periodic).
#
# Parameters are single values (the AWS Config console stores list parameters as strings, which
# Guard 2.x can't use as lists), so they can also be edited in the console.
#
# Usage:  ./deploy-guard-rules.sh            # deploy/update all rules, then trigger evaluation
#         DEBUG_LOGS=true ./deploy-guard-rules.sh
#         ONLY=rcp-deny-uses-org-condition ./deploy-guard-rules.sh   # one rule (or a comma-separated list)
#         PREFIX=orggov- MGMT_ACCOUNT_ID=111122223333 TAG_VALUE=governed ./deploy-guard-rules.sh
#
# TAG_VALUE: value of the "purpose" tag that marks accounts governed by the approved-OU rule.
# Before deploying, edit the per-organization literals described in README.md (email domain,
# management account in the Bedrock ARN regex, approved OU path).
set -euo pipefail
export AWS_PAGER=""
REGION="${REGION:-us-east-1}"
PREFIX="${PREFIX:-orggov-}"
DEBUG_LOGS="${DEBUG_LOGS:-false}"
if [[ -z "${MGMT_ACCOUNT_ID:-}" ]]; then
  MGMT_ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)" \
    || { echo "Could not get the caller identity; check your AWS credentials" >&2; exit 1; }
fi
TAG_VALUE="${TAG_VALUE:-governed}"
RULE_TAG_VALUE="${RULE_TAG_VALUE:-aws-config-organizations-governance}"   # tag applied to each Config rule
# These values are inserted into JSON rule parameters below, so allow only safe characters
[[ "$MGMT_ACCOUNT_ID" =~ ^[0-9]{12}$ ]] || { echo "MGMT_ACCOUNT_ID must be a 12-digit account ID" >&2; exit 1; }
[[ "$TAG_VALUE" =~ ^[A-Za-z0-9_.:/=+@-]+$ && ${#TAG_VALUE} -le 256 ]] || { echo "TAG_VALUE must be 1-256 letters, digits, or _.:/=+@-" >&2; exit 1; }
[[ "$RULE_TAG_VALUE" =~ ^[A-Za-z0-9_.:/=+@-]+$ && ${#RULE_TAG_VALUE} -le 256 ]] || { echo "RULE_TAG_VALUE must be 1-256 letters, digits, or _.:/=+@-" >&2; exit 1; }
[[ "$PREFIX" =~ ^[A-Za-z0-9_-]{0,32}$ ]] || { echo "PREFIX must be letters, digits, hyphens, or underscores" >&2; exit 1; }
[[ "$DEBUG_LOGS" =~ ^(true|false)$ ]] || { echo "DEBUG_LOGS must be true or false" >&2; exit 1; }
case "$REGION" in
  us-east-1|us-gov-west-1) ;;
  *) echo "WARNING: REGION=${REGION}. AWS Config records the AWS Organizations resource types only in us-east-1" \
          "(us-gov-west-1 in AWS GovCloud (US)), so a rule deployed in ${REGION} has nothing to evaluate." >&2 ;;
esac
DIR="$(cd "$(dirname "$0")" && pwd)/guard-rules"

ONLY_LIST=""
if [[ -n "${ONLY:-}" ]]; then ONLY_LIST=",${ONLY// /},"; fi   # "a, b" and "a,b" both work
MATCHED=","

# rule-name-suffix | guard file | resource type | parameters (JSON)
MANIFEST=$(cat <<EOF
org-feature-set-all|org-feature-set-all.guard|AWS::Organizations::Organization|{"expectedFeatureSet":"ALL"}
org-expected-management-account|org-expected-management-account.guard|AWS::Organizations::Organization|{"managementAccountId":"${MGMT_ACCOUNT_ID}"}
account-not-at-root|account-not-at-root.guard|AWS::Organizations::Account|{"managementAccountId":"${MGMT_ACCOUNT_ID}"}
account-approved-parent-ou|tagged-account-in-approved-ou.guard|AWS::Organizations::Account|{"tagValue":"${TAG_VALUE}"}
account-required-owner-tag|account-required-owner-tag.guard|AWS::Organizations::Account|{}
account-email-domain|account-email-domain.guard|AWS::Organizations::Account|{}
ou-max-depth|ou-max-depth.guard|AWS::Organizations::OrganizationalUnit|{}
scp-no-allow-star|scp-no-allow-star.guard|AWS::Organizations::Policy|{}
scp-custom-not-on-root|scp-custom-not-on-root.guard|AWS::Organizations::Policy|{}
rcp-deny-uses-org-condition|rcp-deny-uses-org-condition.guard|AWS::Organizations::Policy|{}
s3-policy-bpa-all|s3-policy-bpa-all.guard|AWS::Organizations::Policy|{}
ec2-declarative-secure-values|ec2-declarative-secure-values.guard|AWS::Organizations::Policy|{}
guardduty-foundational-enabled|guardduty-foundational-enabled.guard|AWS::Organizations::Policy|{}
policy-attached|policy-attached.guard|AWS::Organizations::Policy|{}
org-resource-policy-review|org-resource-policy-review.guard|AWS::Organizations::ResourcePolicy|{}
bedrock-guardrail-enforcement|bedrock-guardrail-enforcement.guard|AWS::Organizations::Policy|{}
ai-optout-all-services|ai-optout-all-services.guard|AWS::Organizations::Policy|{}
backup-plan-minimums|backup-plan-minimums.guard|AWS::Organizations::Policy|{}
upgrade-rollout-safe-order|upgrade-rollout-safe-order.guard|AWS::Organizations::Policy|{}
tag-policy-well-formed|tag-policy-well-formed.guard|AWS::Organizations::Policy|{}
chat-apps-restricted|chat-apps-restricted.guard|AWS::Organizations::Policy|{}
securityhub-all-regions|securityhub-all-regions.guard|AWS::Organizations::Policy|{}
inspector-required-scans|inspector-required-scans.guard|AWS::Organizations::Policy|{}
security-services-child-locked|security-services-child-locked.guard|AWS::Organizations::Policy|{}
EOF
)

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
NAMES=()
while IFS='|' read -r SUFFIX FILE RTYPE PARAMS; do
  [[ -z "$SUFFIX" ]] && continue
  [[ -n "$ONLY_LIST" && "$ONLY_LIST" != *",${SUFFIX},"* ]] && continue
  MATCHED="${MATCHED}${SUFFIX},"
  NAME="${PREFIX}${SUFFIX}"
  python3 - "$NAME" "$DIR/$FILE" "$RTYPE" "$PARAMS" "$DEBUG_LOGS" > "$WORK/rule.json" <<'PY'
import json, sys
name, path, rtype, params, debug = sys.argv[1:6]
policy = open(path).read()
# the "# Description:" comment line in the rule file -> rule description
desc = next((l.split(":", 1)[1].strip() for l in policy.splitlines() if l.startswith("# Description:")), name)
p = json.loads(params)
rule = {
  "ConfigRuleName": name,
  "Description": (desc + (" [parameters managed by deploy-guard-rules.sh - do not edit in console]" if p else ""))[:256],
  "Scope": {"ComplianceResourceTypes": [rtype]},
  "Source": {"Owner": "CUSTOM_POLICY",
             "SourceDetails": [{"EventSource": "aws.config", "MessageType": "ConfigurationItemChangeNotification"},
                               {"EventSource": "aws.config", "MessageType": "OversizedConfigurationItemChangeNotification"}],
             "CustomPolicyDetails": {"PolicyRuntime": "guard-2.x.x", "PolicyText": policy,
                                     "EnableDebugLogDelivery": debug == "true"}}}
if p:
    rule["InputParameters"] = json.dumps(p)
print(json.dumps(rule))
PY
  aws configservice put-config-rule --config-rule "file://$WORK/rule.json" \
    --tags "Key=managed-by,Value=${RULE_TAG_VALUE}" --region "$REGION"
  echo "deployed ${NAME}  (${RTYPE})"
  NAMES+=("$NAME")
done <<< "$MANIFEST"
if [[ -n "$ONLY_LIST" ]]; then
  IFS=',' read -r -a _requested <<< "${ONLY// /}"
  for _r in "${_requested[@]}"; do
    [[ -z "$_r" || "$MATCHED" == *",${_r},"* ]] || echo "WARNING: ONLY name '${_r}' matched no rule" >&2
  done
fi
if [[ ${#NAMES[@]} -eq 0 ]]; then
  echo "No rule matched ONLY='${ONLY:-}'. Use rule names from the manifest, for example ONLY=org-feature-set-all" >&2
  exit 1
fi

# Changing a rule/parameter does not re-evaluate by itself - trigger it (API takes max 25 names).
sleep 10
# Start an evaluation; retry if AWS Config rate-limits the call (the deployment itself already succeeded)
start_evaluation() {
  local attempt err
  for attempt in 1 2 3 4 5; do
    if err="$(aws configservice start-config-rules-evaluation --config-rule-names "$@" --region "$REGION" 2>&1)"; then
      return 0
    fi
    [[ "$err" == *LimitExceeded* ]] || { echo "$err" >&2; return 2; }
    [[ "$attempt" -lt 5 ]] && sleep $((attempt * 10))
  done
  echo "WARNING: AWS Config rate-limited the evaluation request. The rules are deployed and evaluate on the" \
       "next configuration change, or run: aws configservice start-config-rules-evaluation --config-rule-names $*" >&2
  return 1
}
if start_evaluation "${NAMES[@]}"; then
  echo "evaluation started for ${#NAMES[@]} rules"
elif [[ "$?" -eq 2 ]]; then
  exit 1   # the request failed for a reason other than rate limiting
fi
