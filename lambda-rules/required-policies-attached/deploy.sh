#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# Deploy the "required-policies-attached" AWS Config custom Lambda rule.
# Run in the AWS Organizations MANAGEMENT account, us-east-1. Create-or-update; safe to re-run.
#
# Usage:
#   REQUIRED_POLICY_IDS="p-aaaa1111,p-bbbb2222" ./deploy.sh
#   REQUIRED_POLICY_IDS="p-aaaa1111" TARGET_OU_IDS="ou-exmp-11112222" EXCLUDED_OU_IDS="ou-exmp-33334444" ./deploy.sh
#
# REQUIRED_POLICY_IDS  policies (any type: SCP, RCP, declarative) every OU in scope must have attached
#                      directly or through a parent OU / the root
# TARGET_OU_IDS        optional; these OUs and everything below them (default: every OU)
# EXCLUDED_OU_IDS      optional; OUs to skip
# FREQUENCY            periodic evaluation frequency (default TwentyFour_Hours)
# LOG_RETENTION_DAYS   retention for the function's log group (default 90)
#
# The script checks that every policy and OU ID exists before deploying.
set -euo pipefail
export AWS_PAGER=""
REGION="${REGION:-us-east-1}"   # AWS Organizations home Region (us-gov-west-1 in AWS GovCloud (US))
NAME="${NAME:-orggov-required-policies-attached}"
REQUIRED_POLICY_IDS="${REQUIRED_POLICY_IDS:?set REQUIRED_POLICY_IDS=p-...,p-...}"
TARGET_OU_IDS="${TARGET_OU_IDS:-}"
EXCLUDED_OU_IDS="${EXCLUDED_OU_IDS:-}"
FREQUENCY="${FREQUENCY:-TwentyFour_Hours}"
LOG_RETENTION_DAYS="${LOG_RETENTION_DAYS:-90}"
LOG_GROUP="/aws/lambda/${NAME}"

fail() { echo "ERROR: $*" >&2; exit 1; }
case "$REGION" in
  us-east-1|us-gov-west-1) ;;
  *) echo "WARNING: REGION=${REGION}. AWS Config records the AWS Organizations resource types only in us-east-1" \
          "(us-gov-west-1 in AWS GovCloud (US)), so a rule deployed in ${REGION} has nothing to evaluate." >&2 ;;
esac
# Split a comma-separated list, trim spaces, and check each item against a regex
check_ids() {  # check_ids <label> <regex> <csv>
  local item
  IFS=',' read -r -a _items <<< "$3"
  for item in "${_items[@]}"; do
    item="${item// /}"
    [[ -z "$item" ]] && continue
    [[ "$item" =~ $2 ]] || fail "$1 '${item}' is not a valid ID"
    echo "$item"
  done
}
[[ "$NAME" =~ ^[A-Za-z0-9_-]{1,64}$ ]] || fail "NAME must be 1-64 letters, digits, hyphens, or underscores"
case "$FREQUENCY" in One_Hour|Three_Hours|Six_Hours|Twelve_Hours|TwentyFour_Hours) ;;
  *) fail "FREQUENCY must be One_Hour, Three_Hours, Six_Hours, Twelve_Hours, or TwentyFour_Hours" ;; esac
[[ "$LOG_RETENTION_DAYS" =~ ^[0-9]+$ ]] || fail "LOG_RETENTION_DAYS must be a number of days"

IDENTITY="$(aws sts get-caller-identity --query '[Account,Arn]' --output text)" \
  || fail "could not get the caller identity; check your AWS credentials"
read -r ACCOUNT_ID CALLER_ARN <<< "$IDENTITY"
PARTITION="$(cut -d: -f2 <<< "$CALLER_ARN")"   # aws, aws-us-gov, ...
[[ "$ACCOUNT_ID" =~ ^[0-9]{12}$ && -n "$PARTITION" ]] || fail "unexpected caller identity '${IDENTITY}'"

# Validate IDs, then confirm they exist (a typo would otherwise produce misleading results)
POLICY_LIST="$(check_ids "Policy ID" '^p-[0-9a-zA-Z_]{8,128}$' "$REQUIRED_POLICY_IDS")"
[[ -n "$POLICY_LIST" ]] || fail "REQUIRED_POLICY_IDS is empty"
OU_LIST="$(check_ids "OU ID" '^ou-[0-9a-z]{4,32}-[a-z0-9]{8,32}$' "${TARGET_OU_IDS},${EXCLUDED_OU_IDS}")"
for P in $POLICY_LIST; do
  aws organizations describe-policy --policy-id "$P" --query Policy.PolicySummary.Name --output text >/dev/null \
    || fail "policy ${P} not found or not readable"
done
for OU in $OU_LIST; do
  aws organizations describe-organizational-unit --organizational-unit-id "$OU" >/dev/null \
    || fail "OU ${OU} not found or not readable"
done
echo "validated $(echo "$POLICY_LIST" | wc -w | tr -d ' ') policies and $(echo "$OU_LIST" | wc -w | tr -d ' ') OU IDs"

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# 1. Log group with a retention period (created here, so the function doesn't need CreateLogGroup)
if [[ -z "$(aws logs describe-log-groups --region "$REGION" --log-group-name-prefix "$LOG_GROUP" \
      --query "logGroups[?logGroupName=='${LOG_GROUP}'].logGroupName" --output text)" ]]; then
  aws logs create-log-group --region "$REGION" --log-group-name "$LOG_GROUP"
  echo "created log group ${LOG_GROUP}"
fi
aws logs put-retention-policy --region "$REGION" --log-group-name "$LOG_GROUP" \
  --retention-in-days "$LOG_RETENTION_DAYS"

# 2. IAM role for the function: read the organization tree and attachments, report evaluations.
# "Resource": "*" on the read and report actions: organizations:ListRoots and config:PutEvaluations
# don't support resource-level permissions, and the function reads every in-scope OU and its attached
# policies in the one organization this management account belongs to. ListOrganizationalUnitsForParent,
# ListPoliciesForTarget and DescribePolicy can be scoped to root, OU and policy ARNs if you prefer.
cat > "$WORK/trust.json" <<'EOF'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}
EOF
cat > "$WORK/policy.json" <<EOF
{"Version":"2012-10-17","Statement":[
 {"Sid":"ReadOrganization","Effect":"Allow","Action":["organizations:ListRoots","organizations:ListOrganizationalUnitsForParent",
  "organizations:ListPoliciesForTarget","organizations:DescribePolicy"],"Resource":"*"},
 {"Sid":"ReportEvaluations","Effect":"Allow","Action":"config:PutEvaluations","Resource":"*"},
 {"Sid":"Logs","Effect":"Allow","Action":["logs:CreateLogStream","logs:PutLogEvents"],
  "Resource":"arn:${PARTITION}:logs:${REGION}:${ACCOUNT_ID}:log-group:${LOG_GROUP}:*"}]}
EOF
if ! aws iam get-role --role-name "$NAME" >/dev/null 2>&1; then
  aws iam create-role --role-name "$NAME" --assume-role-policy-document "file://$WORK/trust.json" \
    --description "AWS Config rule ${NAME}: read-only AWS Organizations access" >/dev/null
  echo "created role ${NAME}"; sleep 10   # allow IAM propagation before Lambda uses the role
fi
aws iam put-role-policy --role-name "$NAME" --policy-name "${NAME}-permissions" --policy-document "file://$WORK/policy.json"
ROLE_ARN="arn:${PARTITION}:iam::${ACCOUNT_ID}:role/${NAME}"

# 3. Lambda function
( cd "$HERE" && zip -q "$WORK/function.zip" index.py )
if aws lambda get-function --function-name "$NAME" --region "$REGION" >/dev/null 2>&1; then
  aws lambda update-function-code --function-name "$NAME" --zip-file "fileb://$WORK/function.zip" --region "$REGION" >/dev/null
  aws lambda wait function-updated --function-name "$NAME" --region "$REGION"
  echo "updated function ${NAME}"
else
  aws lambda create-function --function-name "$NAME" --runtime python3.13 --handler index.lambda_handler \
    --role "$ROLE_ARN" --zip-file "fileb://$WORK/function.zip" --timeout 120 --memory-size 256 \
    --region "$REGION" >/dev/null
  aws lambda wait function-active-v2 --function-name "$NAME" --region "$REGION"
  echo "created function ${NAME}"
fi
FUNCTION_ARN="arn:${PARTITION}:lambda:${REGION}:${ACCOUNT_ID}:function:${NAME}"

# 4. Allow only AWS Config in this account to invoke the function (added once; errors are not hidden)
if ! aws lambda get-policy --function-name "$NAME" --region "$REGION" --query Policy --output text 2>/dev/null \
     | grep -q '"Sid":"AllowConfigInvoke"'; then
  aws lambda add-permission --function-name "$NAME" --region "$REGION" --statement-id AllowConfigInvoke \
    --action lambda:InvokeFunction --principal config.amazonaws.com --source-account "$ACCOUNT_ID" >/dev/null
  echo "added invoke permission for AWS Config (source account ${ACCOUNT_ID})"
fi

# 5. AWS Config rule: configuration-change triggers for OUs and policies, plus a periodic run
python3 - "$NAME" "$FUNCTION_ARN" "$REQUIRED_POLICY_IDS" "$TARGET_OU_IDS" "$EXCLUDED_OU_IDS" "$FREQUENCY" > "$WORK/rule.json" <<'PY'
import json, sys
name, arn, required, targets, excluded, freq = sys.argv[1:7]
params = {"requiredPolicyIds": required}
if targets: params["targetOuIds"] = targets
if excluded: params["excludedOuIds"] = excluded
print(json.dumps({
  "ConfigRuleName": name,
  "Description": "Required organization policies (SCP, RCP, declarative) are attached to each OU in scope, directly or inherited",
  "Scope": {"ComplianceResourceTypes": ["AWS::Organizations::OrganizationalUnit", "AWS::Organizations::Policy"]},
  "InputParameters": json.dumps(params),
  "MaximumExecutionFrequency": freq,
  "Source": {"Owner": "CUSTOM_LAMBDA", "SourceIdentifier": arn, "SourceDetails": [
      {"EventSource": "aws.config", "MessageType": "ConfigurationItemChangeNotification"},
      {"EventSource": "aws.config", "MessageType": "OversizedConfigurationItemChangeNotification"},
      {"EventSource": "aws.config", "MessageType": "ScheduledNotification", "MaximumExecutionFrequency": freq}]}}))
PY
aws configservice put-config-rule --config-rule "file://$WORK/rule.json" --region "$REGION"
echo "deployed AWS Config rule ${NAME}"
sleep 5
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
if start_evaluation "$NAME"; then
  echo "evaluation started"
elif [[ "$?" -eq 2 ]]; then
  exit 1   # the request failed for a reason other than rate limiting
fi
