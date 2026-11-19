#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
# Org control-plane change alerts -> SNS email:
#   - AWS Config CI changes for AWS::Organizations::* (normal + oversized CIs) via EventBridge
#   - Delegated-admin and trusted-access changes via CloudTrail events (Config doesn't record these)
#   - Changes to this solution's own detection resources (Config recorder and rules, these
#     EventBridge rules, the SNS topic and subscriptions, the DLQ, the Lambda rule, CloudTrail trails)
#   - CloudWatch alarms when alerts land in the dead-letter queue (delivery failures) and when the
#     Lambda rule function fails or is throttled
#   - A warning if no CloudTrail trail is logging (the CloudTrail-based rules need one)
#
# Run in the MANAGEMENT account, us-east-1 (where Config records the global AWS::Organizations::* types).
# Safe to re-run: every call is create-or-update. Re-running also triggers the self-monitoring alert
# for the changes it makes, which is expected.
#
# Usage:
#   1) EMAIL=you@example.com ./org-control-plane-alerts-setup.sh
#   2) Do NOT click the confirmation link. Copy it, then:
#      CONFIRM_URL='<link>' EMAIL=you@example.com ./org-control-plane-alerts-setup.sh
#
# Optional: LAMBDA_FUNCTION_NAME (default orggov-required-policies-attached) is the Lambda rule
# function and IAM role name watched by the self-monitoring rule.
set -euo pipefail

REGION="${REGION:-us-east-1}"
EMAIL="${EMAIL:?set EMAIL=<address to notify>}"
LAMBDA_FUNCTION_NAME="${LAMBDA_FUNCTION_NAME:-orggov-required-policies-attached}"
# Reject values that could break the JSON or JMESPath text built below
if [[ ! "$EMAIL" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
  echo "EMAIL '${EMAIL}' is not a valid email address" >&2; exit 1
fi
if [[ ! "$LAMBDA_FUNCTION_NAME" =~ ^[A-Za-z0-9_-]{1,64}$ ]]; then
  echo "LAMBDA_FUNCTION_NAME must be 1-64 letters, digits, hyphens, or underscores" >&2; exit 1
fi
case "$REGION" in
  us-east-1|us-gov-west-1) ;;
  *) echo "WARNING: REGION=${REGION}. AWS Config records the AWS Organizations resource types only in us-east-1" \
          "(us-gov-west-1 in AWS GovCloud (US)), so alerts deployed in ${REGION} won't see them." >&2 ;;
esac
IDENTITY="$(aws sts get-caller-identity --query '[Account,Arn]' --output text)" \
  || { echo "Could not get the caller identity; check your AWS credentials" >&2; exit 1; }
read -r ACCOUNT_ID CALLER_ARN <<< "$IDENTITY"
PARTITION="$(cut -d: -f2 <<< "$CALLER_ARN")"   # aws, aws-us-gov, ...
if [[ ! "$ACCOUNT_ID" =~ ^[0-9]{12}$ || -z "$PARTITION" ]]; then
  echo "Unexpected caller identity '${IDENTITY}'" >&2; exit 1
fi
TOPIC_NAME="OrgControlPlaneChangeAlerts"
DLQ_NAME="OrgControlPlaneChangeAlerts-DLQ"
RULE_MAIN="OrgControlPlaneConfigChanges"
RULE_OVERSIZED="OrgControlPlaneConfigChangesOversized"
RULE_DELEGATED="OrgDelegatedAdminChanges"
RULE_SELF="OrgGovernanceSelfMonitoring"
RULE_SELF_ALERT="OrgGovernanceAlertingSelfMonitoring"
ALARM_NAME="OrgControlPlaneChangeAlerts-DLQ-NotEmpty"
LAMBDA_ALARM_NAME="OrgGovernanceLambdaRule-ErrorsOrThrottles"
TYPES='["AWS::Organizations::Organization","AWS::Organizations::Account","AWS::Organizations::OrganizationalUnit","AWS::Organizations::Policy","AWS::Organizations::ResourcePolicy"]'
export AWS_PAGER=""
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

echo "Account ${ACCOUNT_ID}, region ${REGION}"

# The delegated-admin and self-monitoring rules match CloudTrail events, which reach EventBridge only
# while a trail is logging management events.
LOGGING=0
for TRAIL in $(aws cloudtrail describe-trails --region "$REGION" --query 'trailList[].TrailARN' --output text); do
  [[ "$(aws cloudtrail get-trail-status --name "$TRAIL" --region "$REGION" --query IsLogging --output text 2>/dev/null)" == "True" ]] || continue
  # AWS Organizations and IAM are global services: their events are logged only by trails that
  # include global service events
  [[ "$(aws cloudtrail get-trail --name "$TRAIL" --region "$REGION" --query Trail.IncludeGlobalServiceEvents --output text 2>/dev/null)" == "True" ]] || continue
  # Count the trail only if its event selectors include write management events
  if aws cloudtrail get-event-selectors --trail-name "$TRAIL" --region "$REGION" --output json 2>/dev/null | python3 -c '
import json, sys
d = json.load(sys.stdin)
basic = any(s.get("IncludeManagementEvents") and s.get("ReadWriteType", "All") in ("All", "WriteOnly")
            for s in d.get("EventSelectors") or [])
def mgmt(sel):
    f = {x["Field"]: x for x in sel.get("FieldSelectors", [])}
    cat = f.get("eventCategory", {}).get("Equals", [])
    ro = f.get("readOnly", {}).get("Equals", [])
    return "Management" in cat and ro != ["true"]
adv = any(mgmt(s) for s in d.get("AdvancedEventSelectors") or [])
sys.exit(0 if basic or adv else 1)'; then
    LOGGING=$((LOGGING + 1))
  fi
done
if [[ "$LOGGING" -eq 0 ]]; then
  echo "WARNING: no CloudTrail trail in ${REGION} is logging write management events, including global service events." \
       "The delegated-admin and self-monitoring alerts need one."
fi

# 1. SNS topic + policy allowing only EventBridge in this account, and this script's two alarms, to publish
TOPIC_ARN="$(aws sns create-topic --name "$TOPIC_NAME" --region "$REGION" --query TopicArn --output text)"
ALARM_ARN="arn:${PARTITION}:cloudwatch:${REGION}:${ACCOUNT_ID}:alarm:${ALARM_NAME}"
LAMBDA_ALARM_ARN="arn:${PARTITION}:cloudwatch:${REGION}:${ACCOUNT_ID}:alarm:${LAMBDA_ALARM_NAME}"
cat > "$WORK/topic-policy.json" <<EOF
{"Version":"2012-10-17","Id":"OrgAlertsTopicPolicy","Statement":[{"Sid":"AllowEventBridgePublish","Effect":"Allow",
"Principal":{"Service":"events.amazonaws.com"},"Action":"sns:Publish","Resource":"${TOPIC_ARN}",
"Condition":{"StringEquals":{"aws:SourceAccount":"${ACCOUNT_ID}"}}},
{"Sid":"AllowAlarmsPublish","Effect":"Allow",
"Principal":{"Service":"cloudwatch.amazonaws.com"},"Action":"sns:Publish","Resource":"${TOPIC_ARN}",
"Condition":{"StringEquals":{"aws:SourceAccount":"${ACCOUNT_ID}"},"ArnEquals":{"aws:SourceArn":["${ALARM_ARN}","${LAMBDA_ALARM_ARN}"]}}}]}
EOF
aws sns set-topic-attributes --topic-arn "$TOPIC_ARN" --attribute-name Policy \
  --attribute-value "file://$WORK/topic-policy.json" --region "$REGION"

# Email subscription.
# IMPORTANT: do NOT click "Confirm subscription" in the email - a click-confirmed subscription can be
# removed by ANYONE who has the email (the unsubscribe link works without credentials, e.g. if the
# alert is forwarded to a list). Instead copy the confirmation link and re-run with CONFIRM_URL so the
# subscription is confirmed with --authenticate-on-unsubscribe (unsubscribe then requires AWS auth).
if [[ -n "${CONFIRM_URL:-}" ]]; then
  # Accept only an Amazon SNS confirmation link for this topic
  TOKEN="$(python3 - "$CONFIRM_URL" "$TOPIC_ARN" "$REGION" <<'PY'
import re, sys, urllib.parse as u
url, topic, region = sys.argv[1:4]
p = u.urlparse(url); q = u.parse_qs(p.query)
if p.scheme != "https" or not re.fullmatch(r"sns\." + re.escape(region) + r"\.amazonaws\.com(\.cn)?", p.hostname or ""):
    sys.exit("CONFIRM_URL is not an Amazon SNS link for " + region)
if q.get("TopicArn", [""])[0] != topic or not q.get("Token"):
    sys.exit("CONFIRM_URL is not a confirmation link for " + topic)
print(q["Token"][0])
PY
)"
  SUB_ARN="$(aws sns confirm-subscription --topic-arn "$TOPIC_ARN" --token "$TOKEN" \
    --authenticate-on-unsubscribe true --region "$REGION" --query SubscriptionArn --output text)"
  echo "Confirmed (authenticated unsubscribe): ${SUB_ARN}"
elif ! aws sns list-subscriptions-by-topic --topic-arn "$TOPIC_ARN" --region "$REGION" \
     --query "Subscriptions[?Endpoint=='${EMAIL}'].SubscriptionArn" --output text | grep -q .; then
  aws sns subscribe --topic-arn "$TOPIC_ARN" --protocol email --notification-endpoint "$EMAIL" --region "$REGION" >/dev/null
  echo "Subscription created. DO NOT click the link in the confirmation email sent to ${EMAIL}."
  echo "Copy the link address and re-run: CONFIRM_URL='<link>' EMAIL=${EMAIL} $0"
fi

# Warn about subscriptions confirmed without authentication (clicked link, or a mail scanner that
# followed it). Anyone holding one of those alert emails can unsubscribe the recipient.
aws sns list-subscriptions-by-topic --topic-arn "$TOPIC_ARN" --region "$REGION" \
  --query 'Subscriptions[].[SubscriptionArn,Endpoint]' --output text |
while read -r SUB ENDPOINT; do
  [[ "$SUB" == arn:* ]] || continue   # PendingConfirmation
  AUTH="$(aws sns get-subscription-attributes --subscription-arn "$SUB" --region "$REGION" \
    --query 'Attributes.ConfirmationWasAuthenticated' --output text)"
  if [[ "$AUTH" != "true" ]]; then
    echo "WARNING: ${ENDPOINT} was confirmed WITHOUT authentication; anyone with an alert email can unsubscribe it."
    echo "  Fix: aws sns unsubscribe --region ${REGION} --subscription-arn ${SUB}"
    echo "       then re-run this script and confirm with CONFIRM_URL (do not click the link)."
  fi
  # A filter policy can silently drop alerts for this recipient (the alerts carry no message attributes)
  FILTER="$(aws sns get-subscription-attributes --subscription-arn "$SUB" --region "$REGION" \
    --query 'Attributes.FilterPolicy' --output text)"
  if [[ -n "$FILTER" && "$FILTER" != "None" ]]; then
    echo "WARNING: ${ENDPOINT} has a subscription filter policy, so it may not receive alerts: ${FILTER}"
    echo "  Fix: aws sns set-subscription-attributes --region ${REGION} --subscription-arn ${SUB} \\"
    echo "         --attribute-name FilterPolicy --attribute-value '{}'"
  fi
done

# 2. Dead-letter queue for failed EventBridge -> SNS deliveries
#    CreateQueue fails if the queue exists with different attributes, so update an existing queue.
DLQ_ATTRS="MessageRetentionPeriod=1209600,SqsManagedSseEnabled=true"
if DLQ_URL="$(aws sqs get-queue-url --queue-name "$DLQ_NAME" --region "$REGION" --query QueueUrl --output text 2>/dev/null)"; then
  aws sqs set-queue-attributes --queue-url "$DLQ_URL" --attributes "$DLQ_ATTRS" --region "$REGION"
else
  DLQ_URL="$(aws sqs create-queue --queue-name "$DLQ_NAME" --attributes "$DLQ_ATTRS" \
    --region "$REGION" --query QueueUrl --output text)"
fi
DLQ_ARN="$(aws sqs get-queue-attributes --queue-url "$DLQ_URL" --attribute-names QueueArn --region "$REGION" --query Attributes.QueueArn --output text)"
RULE_MAIN_ARN="arn:${PARTITION}:events:${REGION}:${ACCOUNT_ID}:rule/${RULE_MAIN}"
RULE_OVS_ARN="arn:${PARTITION}:events:${REGION}:${ACCOUNT_ID}:rule/${RULE_OVERSIZED}"
RULE_DEL_ARN="arn:${PARTITION}:events:${REGION}:${ACCOUNT_ID}:rule/${RULE_DELEGATED}"
RULE_SELF_ARN="arn:${PARTITION}:events:${REGION}:${ACCOUNT_ID}:rule/${RULE_SELF}"
RULE_SELF_ALERT_ARN="arn:${PARTITION}:events:${REGION}:${ACCOUNT_ID}:rule/${RULE_SELF_ALERT}"
python3 - "$DLQ_ARN" "$RULE_MAIN_ARN" "$RULE_OVS_ARN" "$RULE_DEL_ARN" "$RULE_SELF_ARN" "$RULE_SELF_ALERT_ARN" > "$WORK/dlq-attrs.json" <<'PY'
import json, sys
dlq, *rules = sys.argv[1:]
pol = {"Version": "2012-10-17", "Statement": [{"Sid": "AllowEventBridgeDLQ", "Effect": "Allow",
       "Principal": {"Service": "events.amazonaws.com"}, "Action": "sqs:SendMessage", "Resource": dlq,
       "Condition": {"ArnEquals": {"aws:SourceArn": rules}}}]}
print(json.dumps({"Policy": json.dumps(pol)}))
PY
aws sqs set-queue-attributes --queue-url "$DLQ_URL" --attributes "file://$WORK/dlq-attrs.json" --region "$REGION"

# Add or update a rule's targets and stop if EventBridge rejects any of them
put_targets() {  # put_targets <rule> <targets file>
  local failed
  failed="$(aws events put-targets --rule "$1" --targets "file://$2" --region "$REGION" \
    --query FailedEntryCount --output text)"
  if [[ "$failed" != "0" ]]; then
    echo "ERROR: EventBridge rejected ${failed} target(s) for rule $1" >&2; exit 1
  fi
}

# 3. Rule A - normal configuration item change notifications
cat > "$WORK/pattern-main.json" <<EOF
{"source":["aws.config"],"detail-type":["Config Configuration Item Change"],
 "detail":{"messageType":["ConfigurationItemChangeNotification"],
           "configurationItem":{"resourceType":${TYPES}}}}
EOF
aws events put-rule --name "$RULE_MAIN" --event-pattern "file://$WORK/pattern-main.json" --state ENABLED \
  --description "Alerts on AWS Config CI changes to AWS::Organizations::* control-plane resource types" \
  --region "$REGION" >/dev/null

# Multi-line email: InputTemplate must be valid JSON, so each line is its own quoted string,
# separated by real line breaks. (A single string with \n escapes shows literal "\n" in email;
# unquoted text or raw line breaks inside one string are rejected by PutTargets.)
python3 - "$TOPIC_ARN" "$DLQ_ARN" > "$WORK/targets-main.json" <<'PY'
import json, sys
topic, dlq = sys.argv[1:3]
tmpl = "\n".join([
  "AWS Config: org control-plane change detected",
  "",
  "Resource type : <rtype>",
  "Resource ID   : <rid>",
  "Change type   : <ctype>      (CREATE / UPDATE / DELETE)",
  "CI status     : <status>",
  "Captured      : <time>",
  "Account/Region: <acct> / <region>",
  "",
  "What changed (configurationItemDiff.changedProperties):",
  "Note: list items are diffed by content; Statement.N numbers may not match actual positions.",
  "<diff>",
  "",
  "Investigate:",
  " - Who: CloudTrail Event history in the management account, around the captured time",
  " - History: AWS Config console > Resources > <rtype> <rid> > Resource timeline",
])
print(json.dumps([{
  "Id": "OrgAlertsSNS", "Arn": topic,
  "RetryPolicy": {"MaximumRetryAttempts": 185, "MaximumEventAgeInSeconds": 86400},
  "DeadLetterConfig": {"Arn": dlq},
  "InputTransformer": {
    "InputPathsMap": {
      "rtype":  "$.detail.configurationItem.resourceType",
      "rid":    "$.detail.configurationItem.resourceId",
      "status": "$.detail.configurationItem.configurationItemStatus",
      "time":   "$.detail.configurationItem.configurationItemCaptureTime",
      "acct":   "$.detail.configurationItem.awsAccountId",
      "region": "$.detail.configurationItem.awsRegion",
      "ctype":  "$.detail.configurationItemDiff.changeType",
      "diff":   "$.detail.configurationItemDiff.changedProperties"},
    "InputTemplate": "\n".join(json.dumps(line) for line in tmpl.split("\n"))}}]))  # one quoted string per line
PY
put_targets "$RULE_MAIN" "$WORK/targets-main.json"

# 4. Rule B - oversized CI notifications (large policies); payload has configurationItemSummary, no diff
cat > "$WORK/pattern-ovs.json" <<EOF
{"source":["aws.config"],"detail-type":["Config Configuration Item Change"],
 "detail":{"messageType":["OversizedConfigurationItemChangeNotification"],
           "configurationItemSummary":{"resourceType":${TYPES}}}}
EOF
aws events put-rule --name "$RULE_OVERSIZED" --event-pattern "file://$WORK/pattern-ovs.json" --state ENABLED \
  --description "Alerts on OVERSIZED AWS Config CI changes to AWS::Organizations::* types" \
  --region "$REGION" >/dev/null
python3 - "$TOPIC_ARN" "$DLQ_ARN" > "$WORK/targets-ovs.json" <<'PY'
import json, sys
topic, dlq = sys.argv[1:3]
tmpl = "\n".join([
  "AWS Config: org control-plane change detected (OVERSIZED configuration item)",
  "",
  "Resource type : <rtype>",
  "Resource ID   : <rid>",
  "Change type   : <ctype>",
  "CI status     : <status>",
  "Captured      : <time>",
  "Account/Region: <acct> / <region>",
  "",
  "The item was too large to include in the notification - open the Resource timeline",
  "(AWS Config console > Resources > <rtype> <rid>) to see the before/after diff.",
])
print(json.dumps([{
  "Id": "OrgAlertsSNS", "Arn": topic,
  "RetryPolicy": {"MaximumRetryAttempts": 185, "MaximumEventAgeInSeconds": 86400},
  "DeadLetterConfig": {"Arn": dlq},
  "InputTransformer": {
    "InputPathsMap": {
      "rtype":  "$.detail.configurationItemSummary.resourceType",
      "rid":    "$.detail.configurationItemSummary.resourceId",
      "status": "$.detail.configurationItemSummary.configurationItemStatus",
      "time":   "$.detail.configurationItemSummary.configurationItemCaptureTime",
      "acct":   "$.detail.configurationItemSummary.awsAccountId",
      "region": "$.detail.configurationItemSummary.awsRegion",
      "ctype":  "$.detail.configurationItemSummary.changeType"},
    "InputTemplate": "\n".join(json.dumps(line) for line in tmpl.split("\n"))}}]))  # one quoted string per line
PY
put_targets "$RULE_OVERSIZED" "$WORK/targets-ovs.json"

# 5. Rule C - delegated-administrator, trusted-access, organization resource policy, and policy type
#    changes (AWS Config records neither delegated administrators nor trusted access, a change to the
#    resource policy content creates no configuration item, and disabling a policy type on the root
#    detaches every policy of that type at once, so use CloudTrail events).
#    Organizations is global: its CloudTrail events are delivered to EventBridge in us-east-1.
#    Requires a logging CloudTrail trail (any trail capturing management events).
#    Failed attempts (errorCode set) also match - an AccessDenied attempt is worth knowing about.
cat > "$WORK/pattern-del.json" <<'EOF'
{"source":["aws.organizations"],"detail-type":["AWS API Call via CloudTrail"],
 "detail":{"eventSource":["organizations.amazonaws.com"],
           "eventName":["RegisterDelegatedAdministrator","DeregisterDelegatedAdministrator",
                        "EnableAWSServiceAccess","DisableAWSServiceAccess",
                        "PutResourcePolicy","DeleteResourcePolicy",
                        "EnablePolicyType","DisablePolicyType"]}}
EOF
aws events put-rule --name "$RULE_DELEGATED" --event-pattern "file://$WORK/pattern-del.json" --state ENABLED \
  --description "Alerts on AWS Organizations delegated-admin, trusted-access, resource policy, and policy type changes (CloudTrail)" \
  --region "$REGION" >/dev/null
python3 - "$TOPIC_ARN" "$DLQ_ARN" > "$WORK/targets-del.json" <<'PY'
import json, sys
topic, dlq = sys.argv[1:3]
tmpl = "\n".join([
  "AWS Organizations: delegated administrator, trusted access, resource policy, or policy type change",
  "",
  "Action        : <event>",
  "Service       : <svc>      (delegated-admin and trusted-access events only)",
  "Account       : <target>      (delegated-admin events only)",
  "Policy type   : <ptype>      (Enable/DisablePolicyType only; DisablePolicyType detaches all policies of that type)",
  "Who           : <who>",
  "When          : <time>",
  "Source IP     : <ip>",
  "Error (if any): <err> <errmsg>",
  "",
  "Verify current state:",
  " aws organizations list-delegated-administrators --service-principal <svc>",
  " aws organizations list-aws-service-access-for-organization",
  " aws organizations describe-resource-policy     (resource policy content is hidden in CloudTrail)",
  " aws organizations list-roots                   (policy types enabled on the root)",
  "Note: AWS Config doesn't record delegated administrators, trusted access, resource policy content changes, or policy type changes; this alert comes from CloudTrail.",
])
print(json.dumps([{
  "Id": "OrgAlertsSNS", "Arn": topic,
  "RetryPolicy": {"MaximumRetryAttempts": 185, "MaximumEventAgeInSeconds": 86400},
  "DeadLetterConfig": {"Arn": dlq},
  "InputTransformer": {
    "InputPathsMap": {
      "event":  "$.detail.eventName",
      "svc":    "$.detail.requestParameters.servicePrincipal",
      "ptype":  "$.detail.requestParameters.policyType",
      "target": "$.detail.requestParameters.accountId",
      "who":    "$.detail.userIdentity.arn",
      "time":   "$.detail.eventTime",
      "ip":     "$.detail.sourceIPAddress",
      "err":    "$.detail.errorCode",
      "errmsg": "$.detail.errorMessage"},
    "InputTemplate": "\n".join(json.dumps(line) for line in tmpl.split("\n"))}}]))  # one quoted string per line
PY
put_targets "$RULE_DELEGATED" "$WORK/targets-del.json"

# 6. Rules D and E - changes to the detection itself (CloudTrail management events, this Region).
#    Someone who can stop the recorder, delete rules, remove the alert targets, or unsubscribe the
#    recipient can blind the solution; these rules report those changes, including failed attempts.
#    Two rules keep each event pattern under the 2,048-character limit, and each one watches the
#    other, so disabling or deleting one of them is reported by the second.
#    Limits: CloudTrail trail changes made from another Region are delivered to EventBridge in that
#    Region. For stronger protection, also forward these events to a separate security account.
#      D (RULE_SELF):       AWS Config, CloudTrail, the Lambda rule function and its IAM role
#      E (RULE_SELF_ALERT): these EventBridge rules, the SNS topic and subscriptions, the DLQ, the alarms
python3 - "$WORK" "$RULE_MAIN" "$RULE_OVERSIZED" "$RULE_DELEGATED" "$RULE_SELF" "$RULE_SELF_ALERT" \
  "$TOPIC_ARN" "$DLQ_NAME" "$LAMBDA_FUNCTION_NAME" \
  "arn:${PARTITION}:lambda:${REGION}:${ACCOUNT_ID}:function:${LAMBDA_FUNCTION_NAME}" "$ALARM_NAME" \
  "$LAMBDA_ALARM_NAME" <<'PY'
import json, sys
work, r_main, r_ovs, r_del, r_self, r_self_alert, topic, dlq, fn, fn_arn, alarm, fn_alarm = sys.argv[1:13]
alarms = [alarm, fn_alarm]
rules = [r_main, r_ovs, r_del, r_self, r_self_alert]
lambda_ops = ["UpdateFunctionCode", "UpdateFunctionConfiguration", "DeleteFunction",
              "AddPermission", "RemovePermission", "PutFunctionConcurrency", "DeleteFunctionConcurrency",
              "PutFunctionEventInvokeConfig", "UpdateFunctionEventInvokeConfig",
              "DeleteFunctionEventInvokeConfig", "CreateFunctionUrlConfig", "UpdateFunctionUrlConfig",
              "DeleteFunctionUrlConfig"]   # CloudTrail adds API-version suffixes
detection = [
  {"source": ["aws.config"], "detail": {"eventName": [
      "StopConfigurationRecorder", "DeleteConfigurationRecorder", "PutConfigurationRecorder",
      "AssociateResourceTypes", "DisassociateResourceTypes", "PutDeliveryChannel",
      "DeleteDeliveryChannel", "PutRetentionConfiguration", "DeleteRetentionConfiguration",
      "PutConfigRule", "DeleteConfigRule", "PutConformancePack", "DeleteConformancePack",
      "DeleteEvaluationResults"]}},
  {"source": ["aws.cloudtrail"], "detail": {"eventName": [
      "StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"]}},
  {"source": ["aws.lambda"], "detail": {"eventName": [{"prefix": op} for op in lambda_ops],
      # name, partial ARN, or full ARN, each with or without a :qualifier (also matches names that
      # end with this name, which only adds alerts)
      "requestParameters": {"functionName": [{"wildcard": "*" + fn}, {"wildcard": "*" + fn + ":*"}]}}},
  {"source": ["aws.iam"], "detail": {"eventName": [
      "PutRolePolicy", "DeleteRolePolicy", "AttachRolePolicy", "DetachRolePolicy",
      "UpdateAssumeRolePolicy", "PutRolePermissionsBoundary", "DeleteRolePermissionsBoundary",
      "DeleteRole"], "requestParameters": {"roleName": [{"equals-ignore-case": fn}]}}},   # IAM names ignore case
  # rule E is watched here, so disabling or deleting it is reported
  {"source": ["aws.events"], "detail": {"eventName": ["PutRule", "DisableRule", "DeleteRule"],
      "requestParameters": {"name": [r_self_alert]}}},
  {"source": ["aws.events"], "detail": {"eventName": ["PutTargets", "RemoveTargets"],
      "requestParameters": {"rule": [r_self_alert]}}},
]
alerting = [
  {"source": ["aws.events"], "detail": {"eventName": ["PutRule", "DisableRule", "DeleteRule"],
      "requestParameters": {"name": rules}}},
  {"source": ["aws.events"], "detail": {"eventName": ["PutTargets", "RemoveTargets"],
      "requestParameters": {"rule": rules}}},
  {"source": ["aws.sns"], "detail": {"eventName": ["DeleteTopic", "SetTopicAttributes", "Subscribe",
      "AddPermission", "RemovePermission"], "requestParameters": {"topicArn": [topic]}}},
  {"source": ["aws.sns"], "detail": {"eventName": ["PutDataProtectionPolicy"],
      "requestParameters": {"resourceArn": [topic]}}},
  {"source": ["aws.sns"], "detail": {"eventName": ["Unsubscribe", "SetSubscriptionAttributes"],
      "requestParameters": {"subscriptionArn": [{"prefix": topic + ":"}]}}},
  {"source": ["aws.sqs"], "detail": {"eventName": ["DeleteQueue", "PurgeQueue", "SetQueueAttributes",
      "AddPermission", "RemovePermission"],
      "requestParameters": {"queueUrl": [{"suffix": "/" + dlq}]}}},
  {"source": ["aws.monitoring"], "detail": {"eventName": ["DeleteAlarms", "DisableAlarmActions"],
      "requestParameters": {"alarmNames": alarms}}},
  {"source": ["aws.monitoring"], "detail": {"eventName": ["PutMetricAlarm", "SetAlarmState"],
      "requestParameters": {"alarmName": alarms}}},
]
for name, alts in (("pattern-self.json", detection), ("pattern-self-alert.json", alerting)):
    text = json.dumps({"detail-type": ["AWS API Call via CloudTrail"], "$or": alts}, separators=(",", ":"))
    if len(text) > 2048:
        sys.exit(f"{name} is {len(text)} characters; EventBridge allows 2048")
    with open(f"{work}/{name}", "w", encoding="utf-8") as f:
        f.write(text)
PY
python3 - "$TOPIC_ARN" "$DLQ_ARN" > "$WORK/targets-self.json" <<'PY'
import json, sys
topic, dlq = sys.argv[1:3]
# Only identifier fields: EventBridge doesn't escape inserted values, and full request parameters
# often contain JSON documents (policies, patterns) that would make the message invalid.
# Fields that aren't in an event are left empty.
RES = {
  "r_name": "$.detail.requestParameters.name",                      # EventBridge rule, trail
  "r_rule": "$.detail.requestParameters.rule",                      # EventBridge targets
  "r_topic": "$.detail.requestParameters.topicArn",                 # SNS topic
  "r_sub": "$.detail.requestParameters.subscriptionArn",            # SNS subscription
  "r_queue": "$.detail.requestParameters.queueUrl",                 # SQS
  "r_alarm": "$.detail.requestParameters.alarmName",                # CloudWatch
  "r_fn": "$.detail.requestParameters.functionName",                # Lambda
  "r_role": "$.detail.requestParameters.roleName",                  # IAM
  "r_cfgrule": "$.detail.requestParameters.configRuleName",         # DeleteConfigRule
  "r_cfgrule2": "$.detail.requestParameters.configRule.configRuleName",  # PutConfigRule
  "r_pack": "$.detail.requestParameters.conformancePackName",       # conformance pack
  "r_rec": "$.detail.requestParameters.configurationRecorderName",  # recorder
}
tmpl = "\n".join([
  "AWS Organizations governance: change to the detection setup",
  "",
  "Action        : <event>  (<src>)",
  "Who           : <who>",
  "When          : <time>",
  "Region        : <region>",
  "Source IP     : <ip>",
  "Error (if any): <err> <errmsg>",
  "",
  "Resource      : " + " ".join(f"<{k}>" for k in RES),
  "",
  "Full request parameters: CloudTrail Event history, filter on the event name above.",
  "",
  "If you didn't expect this change, review it in CloudTrail Event history and re-run the",
  "setup scripts to restore the AWS Config rules, alerts, and Lambda rule.",
])
print(json.dumps([{
  "Id": "OrgAlertsSNS", "Arn": topic,
  "RetryPolicy": {"MaximumRetryAttempts": 185, "MaximumEventAgeInSeconds": 86400},
  "DeadLetterConfig": {"Arn": dlq},
  "InputTransformer": {
    "InputPathsMap": {
      "event":  "$.detail.eventName",
      "src":    "$.detail.eventSource",
      "who":    "$.detail.userIdentity.arn",
      "time":   "$.detail.eventTime",
      "region": "$.detail.awsRegion",
      "ip":     "$.detail.sourceIPAddress",
      "err":    "$.detail.errorCode",
      "errmsg": "$.detail.errorMessage",
      **RES},
    "InputTemplate": "\n".join(json.dumps(line) for line in tmpl.split("\n"))}}]))  # one quoted string per line
PY
aws events put-rule --name "$RULE_SELF" --event-pattern "file://$WORK/pattern-self.json" --state ENABLED \
  --description "Alerts on changes to AWS Config, CloudTrail, and the Lambda rule that this solution relies on" \
  --region "$REGION" >/dev/null
aws events put-rule --name "$RULE_SELF_ALERT" --event-pattern "file://$WORK/pattern-self-alert.json" --state ENABLED \
  --description "Alerts on changes to the EventBridge rules, SNS topic, DLQ, and alarms of the org control-plane alerts" \
  --region "$REGION" >/dev/null
for R in "$RULE_SELF" "$RULE_SELF_ALERT"; do
  put_targets "$R" "$WORK/targets-self.json"
done

# 7. CloudWatch alarms. Both notify the same topic, so if the topic itself is broken, check the
#    alarm states in the CloudWatch console (or forward events to a security account, see README).
#    a) New messages in the dead-letter queue (failed deliveries). A rate metric, so every new
#       failure period alerts again instead of the alarm staying in ALARM.
aws cloudwatch put-metric-alarm --region "$REGION" --alarm-name "$ALARM_NAME" \
  --alarm-description "Org control-plane alerts failed to reach Amazon SNS and were sent to ${DLQ_NAME}" \
  --namespace AWS/SQS --metric-name NumberOfMessagesSent \
  --dimensions "Name=QueueName,Value=${DLQ_NAME}" --statistic Sum --period 300 \
  --evaluation-periods 1 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold \
  --treat-missing-data notBreaching --alarm-actions "$TOPIC_ARN"
#    b) The Lambda rule function failed, was throttled, or dropped events, so AWS Config may still
#       show old results.
#       Harmless if you don't deploy the Lambda rule (no data, alarm stays OK).
python3 - "$LAMBDA_FUNCTION_NAME" > "$WORK/lambda-alarm-metrics.json" <<'PY'
import json, sys
fn = sys.argv[1]
def metric(i, name):
    return {"Id": i, "ReturnData": False, "MetricStat": {"Period": 300, "Stat": "Sum", "Metric": {
        "Namespace": "AWS/Lambda", "MetricName": name, "Dimensions": [{"Name": "FunctionName", "Value": fn}]}}}
# AWS Config invokes the function asynchronously; AsyncEventsDropped counts events that Lambda
# discarded without running the function. FILL treats a missing metric as 0.
print(json.dumps([metric("errors", "Errors"), metric("throttles", "Throttles"),
                  metric("dropped", "AsyncEventsDropped"),
                  {"Id": "failures", "Expression": "FILL(errors, 0) + FILL(throttles, 0) + FILL(dropped, 0)",
                   "Label": "Errors + Throttles + dropped events", "ReturnData": True}]))
PY
aws cloudwatch put-metric-alarm --region "$REGION" --alarm-name "$LAMBDA_ALARM_NAME" \
  --alarm-description "AWS Config Lambda rule ${LAMBDA_FUNCTION_NAME} failed, was throttled, or dropped events; its results may be stale" \
  --metrics "file://$WORK/lambda-alarm-metrics.json" --evaluation-periods 1 --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold --treat-missing-data notBreaching \
  --alarm-actions "$TOPIC_ARN"

echo "Done. Topic: ${TOPIC_ARN}"
echo "Rules: ${RULE_MAIN}, ${RULE_OVERSIZED}, ${RULE_DELEGATED}, ${RULE_SELF}, ${RULE_SELF_ALERT}   DLQ: ${DLQ_ARN}"
echo "Alarms: ${ALARM_NAME}, ${LAMBDA_ALARM_NAME}"
