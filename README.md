# Building governance for your AWS Organizations control plane

This solution uses [AWS Config](https://aws.amazon.com/config/) to inventory, track, alert on, and
continuously evaluate the [AWS Organizations](https://aws.amazon.com/organizations/) control plane:
the organization itself, its accounts and organizational units (OUs), and every type of
organization policy.

> **Note:** This is a sample solution for educational purposes. Any applications you integrate
> these examples into should be thoroughly tested, secured, and optimized according to your
> organization's security standards and policies before deploying to production.

## Table of contents

- [Overview](#overview)
- [How it works](#how-it-works)
- [Architecture](#architecture)
- [Repository contents](#repository-contents)
- [What AWS Config records](#what-aws-config-records)
- [Prerequisites](#prerequisites)
- [Cost](#cost)
- [Customize before you deploy](#customize-before-you-deploy)
- [Deploy](#deploy)
- [Verify](#verify)
- [Explore the recorded data](#explore-the-recorded-data)
- [Rules](#rules)
- [Lambda rule example: required policies attached to every OU](#lambda-rule-example-required-policies-attached-to-every-ou)
- [Using an AWS Config delegated administrator](#using-an-aws-config-delegated-administrator)
- [Testing and writing rules](#testing-and-writing-rules)
- [Limits](#limits)
- [Clean up](#clean-up)
- [Security](#security)
- [License](#license)
- [References](#references)

## Overview

Changes to the AWS Organizations control plane have a wide blast radius. Moving an account to a
different OU changes which policies apply to it, a single edit to a service control policy (SCP)
can affect every account below it, and declarative policies configure services such as Amazon EC2,
Amazon Bedrock, AWS Security Hub, and Amazon Inspector across the organization. Many organizations
write their own policies and standards for this layer, and need to answer questions such as:

- Which accounts are under this OU, and where was this account last week?
- What did this policy look like before it changed, and who changed it?
- Does every policy follow our standards (for example, no `Allow *` in SCPs, or Amazon Bedrock
  guardrails that guard all content)?
- Am I notified when the organization, an account, an OU, or a policy changes?

AWS Config records the AWS Organizations resource types as configuration items, including the full
document of every organization policy type. This solution builds on that to provide:

- **Inventory and history:** query the organization's accounts, OUs, and policies, and investigate
  changes with the AWS Config resource timeline.
- **Near real-time alerts:** email notifications, with the configuration diff, when the
  organization, an account, an OU, or a policy changes, plus alerts for delegated administrator,
  trusted access, organization resource policy, and policy type changes, which AWS Config doesn't
  record.
- **Continuous compliance:** 24 AWS Config custom policy rules written in
  [AWS CloudFormation Guard](https://docs.aws.amazon.com/cfn-guard/latest/ug/what-is-guard.html),
  packaged as a conformance pack, plus an AWS Lambda custom rule example for checks that Guard
  can't do.

**Relationship to AWS Control Tower:** if you use [AWS Control Tower](https://aws.amazon.com/controltower/),
its controls and [drift detection](https://docs.aws.amazon.com/controltower/latest/userguide/governance-drift.html)
cover the policies that AWS Control Tower creates. This solution covers every organization policy,
including the ones you write, of every policy type, and your own standards for the organization
structure. It doesn't require AWS Control Tower, and the two work well together.

## How it works

1. The AWS Config recorder in the management account, in US East (N. Virginia) (`us-east-1`),
   records the `AWS::Organizations::*` resource types.
2. A conformance pack of 24 Guard rules evaluates each configuration item when it changes. Results
   appear in AWS Config and, if you record `AWS::Config::ResourceCompliance`, on each resource's
   timeline.
3. Amazon EventBridge rules match AWS Config configuration item change events for the five
   AWS Organizations types and send a formatted email, with the change type and the configuration
   diff, through Amazon SNS. Oversized configuration items, which carry no diff, get an email that
   points to the resource timeline instead.
4. A separate Amazon EventBridge rule matches AWS CloudTrail events for delegated administrator
   registration, trusted access, organization resource policy, and policy type changes, which AWS
   Config doesn't record.
5. Two self-monitoring Amazon EventBridge rules report changes to the solution's own resources
   (for example, a stopped AWS Config recorder, a deleted rule, a removed alert target, or an
   unsubscribed recipient), so that most changes that would turn off the detection are reported
   (see the limits of self-monitoring in [Step 2: Deploy the alerts](#step-2-deploy-the-alerts)).
6. Failed deliveries go to an Amazon SQS dead-letter queue. Amazon CloudWatch alarms notify you when
   a message arrives there, and when the optional AWS Lambda rule fails, is throttled, or drops
   events.
7. Optionally, an AWS Lambda custom rule checks that required policies reach every OU in scope,
   directly or through inheritance.

## Architecture

```
                     Management account, us-east-1
┌──────────────────────────────────────────────────────────────────────────┐
│ AWS Config recorder ── AWS::Organizations::* configuration items         │
│     │                       │                                            │
│     │                       ├─► Conformance pack: 24 Guard rules         │
│     │                       │   (compliance results, resource timeline)  │
│     │                       └─► Optional: AWS Lambda custom rule         │
│     │                           (required policies attached to each OU)  │
│     ▼                                                                    │
│ EventBridge: Config CI change (normal + oversized) ─┐                    │
│ EventBridge: CloudTrail Register/Deregister         ├─► SNS ─► email     │
│              DelegatedAdministrator, Enable/Disable │   (DLQ: SQS)       │
│              AWSServiceAccess, Put/DeleteResource-  │      │             │
│              Policy, Enable/DisablePolicyType       │      │             │
│ EventBridge: self-monitoring (2 rules) ─────────────┤      ▼             │
│ CloudWatch alarms: DLQ, Lambda rule errors ─────────┘   SQS DLQ          │
└──────────────────────────────────────────────────────────────────────────┘
```

Everything is deployed in the management account in `us-east-1`, the AWS Organizations home Region
in the commercial partition and the only Region where AWS Config records the AWS Organizations
resource types (AWS GovCloud (US-West) in AWS GovCloud (US)).

## Repository contents

| Component | What it does |
|---|---|
| [`guard-rules/`](guard-rules/) | 24 AWS Config custom policy rules written in Guard (runtime `guard-2.x.x`) |
| [`conformance-pack-orgs-control-plane.yaml`](conformance-pack-orgs-control-plane.yaml) | The 24 rules packaged as an AWS Config conformance pack (generated) |
| [`build-conformance-pack.py`](build-conformance-pack.py) | Generates the conformance pack from `guard-rules/` |
| [`deploy-guard-rules.sh`](deploy-guard-rules.sh) | Deploys the rules as standalone AWS Config rules (useful while developing rules) |
| [`org-control-plane-alerts-setup.sh`](org-control-plane-alerts-setup.sh) | [Amazon EventBridge](https://aws.amazon.com/eventbridge/) + [Amazon Simple Notification Service (Amazon SNS)](https://aws.amazon.com/sns/) email alerts for AWS Organizations configuration changes, delegated administrator, trusted access, resource policy, and policy type changes, and changes to the solution itself |
| [`lambda-rules/required-policies-attached/`](lambda-rules/required-policies-attached/) | Custom [AWS Lambda](https://aws.amazon.com/lambda/) rule: required SCPs, RCPs, or declarative policies are attached to every OU in scope (directly or inherited), with unit tests and a deployment script |
| [`tests/run_tests.py`](tests/run_tests.py) | Local test suite (99 cases) using synthetic configuration items |

## What AWS Config records

| Resource type | What the configuration item contains | Example governance use |
|---|---|---|
| `AWS::Organizations::Organization` | Organization ID, ARN, root ID, feature set, management account | Confirm the organization uses all features, which organization policies require, and has the expected management account |
| `AWS::Organizations::Account` | Account ID, name, email, status, join method and time, parent (`ParentIds`), full path from the root (`Paths`), tags | Account inventory; OU-placement history |
| `AWS::Organizations::OrganizationalUnit` | OU ID, name, parent (`ParentId`), full path from the root (`Path`), tags | OU structure baseline and change detection |
| `AWS::Organizations::Policy` | Policy ID, name, type, AWS-managed flag, `TargetIds`, tags, and the full policy document (the description is redacted) | Policy change history and content evaluation for every policy type |
| `AWS::Organizations::ResourcePolicy` | The organization's resource-based delegation policy (ID, ARN, tags; the policy content is redacted) | Detect that the delegation policy exists or was deleted |

Things to know before you start:

- **Every policy type shares one resource type.** SCPs, resource control policies (RCPs), and all
  declarative policy types (for example Amazon EC2, Amazon S3, Amazon GuardDuty, AWS Security Hub,
  Amazon Inspector, Amazon Bedrock, AWS Backup, tag, AI services opt-out, chat applications, and
  upgrade rollout policies) are `AWS::Organizations::Policy`, distinguished by
  `configuration.Type`.
- **Attachment is recorded, inheritance is not.** A policy configuration item lists where the
  policy is attached (`TargetIds`). It doesn't show what each account effectively inherits. Use the
  AWS Lambda rule pattern in this repository for inheritance checks.
- **Some fields are redacted.** Policy descriptions and the content of the organization resource
  policy appear as `"REDACTED"`. A change to the resource policy content doesn't create a new
  configuration item, so AWS Config doesn't show which permissions the policy delegates or when they
  changed. The AWS CloudTrail `PutResourcePolicy` event records who changed the policy and when (the
  content is hidden there too), and `DescribeResourcePolicy` returns the current content.
- **Global resource types, one Region.** These types are recorded in the management account in
  the AWS Organizations home Region: US East (N. Virginia) in the commercial partition, and
  AWS GovCloud (US-West) in the AWS GovCloud (US) partition. See
  [Recording AWS resources](https://docs.aws.amazon.com/config/latest/developerguide/select-resources.html).
- **Commercial partition by default.** The examples target US East (N. Virginia). The same building
  blocks apply to AWS GovCloud (US): run the scripts with `REGION=us-gov-west-1` and use
  `--region us-gov-west-1` in the commands. The scripts take the partition from your credentials,
  and the Amazon Bedrock rule accepts both `arn:aws:` and `arn:aws-us-gov:` guardrail ARNs. Check
  [service availability in AWS GovCloud (US)](https://docs.aws.amazon.com/govcloud-us/latest/UserGuide/using-services.html)
  for each service used. This repository was tested in the commercial partition only.
- **Not recorded:** delegated administrator registrations, trusted access (AWS service access), and
  changes to the organization resource policy content. The alerting script covers these with AWS
  CloudTrail events. Deleting the resource policy is recorded (`ResourceDeleted`), and a re-created
  policy appears as a new resource with a new ID and no tags.

## Prerequisites

- An organization in AWS Organizations with all features enabled, and credentials for its
  **management account**.
- AWS Config enabled in the management account in **US East (N. Virginia) (`us-east-1`)**.
  - **Recommended:** record all supported resource types (`ALL_SUPPORTED_RESOURCE_TYPES`), scoped
    to your organization's risk appetite and profile. New resource types are then recorded
    automatically.
  - **Minimum for this solution:** an inclusion list (`INCLUSION_BY_RESOURCE_TYPES`) in `us-east-1`
    with the five AWS Organizations types, plus optionally `AWS::Config::ResourceCompliance` for
    compliance history on the resource timeline. This reduces recorded configuration items, but new
    resource types aren't added automatically. Example recording group:

    ```json
    "recordingGroup": {
      "allSupported": false,
      "includeGlobalResourceTypes": false,
      "recordingStrategy": { "useOnly": "INCLUSION_BY_RESOURCE_TYPES" },
      "resourceTypes": [
        "AWS::Organizations::Organization",
        "AWS::Organizations::Account",
        "AWS::Organizations::OrganizationalUnit",
        "AWS::Organizations::Policy",
        "AWS::Organizations::ResourcePolicy",
        "AWS::Config::ResourceCompliance"
      ]
    }
    ```

  Confirm the recorder settings:

  ```bash
  aws configservice describe-configuration-recorders --region us-east-1 \
    --query 'ConfigurationRecorders[].recordingGroup.[recordingStrategy.useOnly,resourceTypes]'
  ```

- The latest version of the [AWS Command Line Interface (AWS CLI)](https://aws.amazon.com/cli/),
  Python 3.9+, and `zip` (for the Lambda rule).
- A bash shell. The scripts run on Linux and macOS, and in
  [AWS CloudShell](https://aws.amazon.com/cloudshell/), which already includes the AWS CLI, Python 3,
  and `zip`. On Windows, use AWS CloudShell or the Windows Subsystem for Linux (WSL); the scripts
  don't run in PowerShell or Command Prompt.
- For local tests: the [cfn-guard CLI](https://docs.aws.amazon.com/cfn-guard/latest/ug/setting-up.html).
- For the delegated administrator, trusted access, resource policy, policy type, and self-monitoring
  alerts: an [AWS CloudTrail](https://aws.amazon.com/cloudtrail/) trail that logs management events.
- AWS Identity and Access Management (IAM) permissions in the management account to create AWS
  Config rules and conformance packs, Amazon EventBridge rules, an Amazon SNS topic, an Amazon SQS
  queue, and Amazon CloudWatch alarms, and to read AWS CloudTrail trails, their status, and their
  event selectors (`cloudtrail:DescribeTrails`, `GetTrail`, `GetTrailStatus`, `GetEventSelectors`),
  and Amazon SNS subscription attributes. For the Lambda rule,
  also permissions to create an IAM role (including `iam:PassRole`), a Lambda function, and a
  CloudWatch Logs log group, and to read AWS Organizations policies and OUs.

## Cost

| Component | Cost |
|---|---|
| AWS Config configuration items | Charged per configuration item recorded. With the minimum inclusion list, only changes to the organization, accounts, OUs, and policies are recorded |
| AWS Config rule evaluations | Charged per evaluation, including conformance pack rules. Guard rules are change-triggered, so evaluations follow the rate of control-plane changes |
| Amazon EventBridge | No charge for AWS service events delivered to rules in the default event bus |
| Amazon SNS email notifications | Charged per notification beyond the free tier |
| Amazon SQS dead-letter queue | Charged per request (typically none, unless deliveries fail) |
| Amazon CloudWatch alarms | Two standard-resolution alarms with four metrics in total (dead-letter queue; Lambda rule errors, throttles, and dropped events), charged per alarm metric per month |
| Amazon CloudWatch Logs | Lambda rule logs (90-day retention by default) and optional Guard rule debug logs, charged per GB ingested and stored |
| AWS Lambda rule (optional) | Charged per invocation and duration; runs on OU and policy changes and once per `FREQUENCY` |

See [AWS Config pricing](https://aws.amazon.com/config/pricing/),
[Amazon EventBridge pricing](https://aws.amazon.com/eventbridge/pricing/),
[Amazon SNS pricing](https://aws.amazon.com/sns/pricing/),
[Amazon SQS pricing](https://aws.amazon.com/sqs/pricing/),
[Amazon CloudWatch pricing](https://aws.amazon.com/cloudwatch/pricing/), and
[AWS Lambda pricing](https://aws.amazon.com/lambda/pricing/).

## Customize before you deploy

Guard 2.x regular expressions must be literal, so three rules contain values you **must edit** for
your organization:

| Rule file | What to change | Placeholder |
|---|---|---|
| `guard-rules/account-email-domain.guard` | Approved root-user email domain | `@example\.com$` |
| `guard-rules/bedrock-guardrail-enforcement.guard` | Management account ID in the guardrail ARN regex | `111122223333` |
| `guard-rules/tagged-account-in-approved-ou.guard` | Organization ID, root ID, and approved OU ID in the `Paths` regex | `o-exampleorgid`, `r-exmp`, `ou-exmp-approved` |

Write `/` as `\x2F` inside regular expressions. Other values are rule parameters:

| Parameter (pack / rule) | Used by | Default |
|---|---|---|
| `ExpectedFeatureSet` / `expectedFeatureSet` | `org-feature-set-all` | `ALL` |
| `ManagementAccountId` / `managementAccountId` | `org-expected-management-account`, `account-not-at-root` | `111122223333` (pack) / caller account (script) |
| `GovernedTagValue` / `tagValue` | `account-approved-parent-ou` (accounts tagged `purpose=<value>`) | `governed` |

`deploy-guard-rules.sh` reads these values from the environment variables `MGMT_ACCOUNT_ID`
(default: the caller account) and `TAG_VALUE` (default `governed`), and also accepts `PREFIX`
(default `orggov-`) and `REGION` (default `us-east-1`).

Other literals you may want to adapt: the required account tag key (`owner`), maximum OU depth (3),
minimum backup retention (35 days), the production tag key for upgrade rollout (`environment`), and
the required [Amazon Inspector](https://aws.amazon.com/inspector/) scan types.

After editing rules, run the tests and regenerate the pack:

```bash
python3 tests/run_tests.py
python3 build-conformance-pack.py
```

## Deploy

All commands run in the management account in `us-east-1`.

### Step 1: Deploy the rules

#### Option A: Conformance pack (recommended)

```bash
aws configservice put-conformance-pack --region us-east-1 \
  --conformance-pack-name organizations-control-plane-governance \
  --template-body file://conformance-pack-orgs-control-plane.yaml \
  --conformance-pack-input-parameters \
      ParameterName=ManagementAccountId,ParameterValue=<your-management-account-id> \
      ParameterName=GovernedTagValue,ParameterValue=governed
```

Deploy it as an **account-level** pack in the management account. An organization conformance pack
would add rules to member accounts, which have no AWS Organizations configuration items to evaluate.

After the pack reaches `CREATE_COMPLETE`, start an evaluation so that every rule evaluates the
existing resources right away:

```bash
aws configservice describe-conformance-pack-compliance --region us-east-1 \
  --conformance-pack-name organizations-control-plane-governance \
  --query 'ConformancePackRuleComplianceList[].ConfigRuleName' --output text \
  | xargs aws configservice start-config-rules-evaluation --region us-east-1 --config-rule-names
```

#### Option B: Standalone rules (for rule development)

```bash
./deploy-guard-rules.sh                                   # all rules, prefix orggov-
ONLY=bedrock-guardrail-enforcement DEBUG_LOGS=true ./deploy-guard-rules.sh
```

Debug logs are delivered to [Amazon CloudWatch](https://aws.amazon.com/cloudwatch/) Logs under
`/aws/config/config-rule/<rule-name>/`.

### Step 2: Deploy the alerts

```bash
EMAIL=governance-team@example.com ./org-control-plane-alerts-setup.sh
# Do NOT click "Confirm subscription" in the email. Copy the link address, then:
CONFIRM_URL='<copied link>' EMAIL=governance-team@example.com ./org-control-plane-alerts-setup.sh
```

Alert emails contain organization data, and the script doesn't enable server-side encryption on the
Amazon SNS topic. Before you choose the recipient, read [Security](#security).

Confirming through the script uses `--authenticate-on-unsubscribe true`, so a forwarded alert can't
be used to unsubscribe the recipient. In the change emails, AWS Config compares list items, such as
policy statements, by content: an edited statement appears as one deleted and one created entry,
and the index numbers might not match the statement's position. The script is safe to re-run and creates:

- `OrgControlPlaneConfigChanges` / `OrgControlPlaneConfigChangesOversized`: AWS Config
  configuration item changes for the five AWS Organizations types, with change type, status, and
  the configuration diff.
- `OrgDelegatedAdminChanges`: AWS CloudTrail events for delegated administrator, trusted access,
  organization resource policy (`PutResourcePolicy`, `DeleteResourcePolicy`), and policy type
  (`EnablePolicyType`, `DisablePolicyType`) changes, including the caller. Disabling a policy type
  on the root detaches every policy of that type from the whole organization at once. If your
  resource policy delegates `EnablePolicyType` or `DisablePolicyType` to a member account, those
  calls are logged in that member account, so this rule doesn't see them; monitor that account too.
  CloudTrail hides the resource policy content, so the email tells you who changed it and when. When you get this alert, remove the `reviewed=true` tag from the resource policy, review the
  current content with `aws organizations describe-resource-policy`, and add the tag back when you're
  done. The `org-resource-policy-review` rule can't detect a content change, so without this step
  the tag would stay on a policy that changed after its review.
- `OrgGovernanceSelfMonitoring`: AWS CloudTrail events that change AWS Config (the recorder and its
  recorded resource types, the delivery channel, the retention period, rules, and conformance
  packs), CloudTrail trails, or the Lambda rule's function (code, configuration, concurrency,
  permissions, asynchronous invocation settings, and function URLs; by name, partial ARN, or full
  ARN, with or without a version or alias) and IAM role (policies, permissions boundary, trust
  policy).
- `OrgGovernanceAlertingSelfMonitoring`: AWS CloudTrail events that change the alert rules, their
  targets, the Amazon SNS topic (including its permissions and data protection policy) and
  subscriptions, the dead-letter queue, or the alarms (including a manually set alarm state). The two
  self-monitoring rules watch each other, so disabling or deleting one is reported by the other.
  Failed attempts (for example, `AccessDenied`) are reported too.
- Amazon SNS topic `OrgControlPlaneChangeAlerts` (the topic policy allows Amazon EventBridge and the
  two alarms in your account to publish) and
  [Amazon Simple Queue Service (Amazon SQS)](https://aws.amazon.com/sqs/) dead-letter queue
  `OrgControlPlaneChangeAlerts-DLQ` (server-side encryption enabled).
- Amazon CloudWatch alarm `OrgControlPlaneChangeAlerts-DLQ-NotEmpty`, which notifies the topic when
  alerts can't be delivered and land in the dead-letter queue. It returns to `OK` after a 5-minute
  period without failures, so a later failure notifies you again.
- Amazon CloudWatch alarm `OrgGovernanceLambdaRule-ErrorsOrThrottles`, which notifies the topic when
  the Lambda rule function fails, is throttled, or drops events that AWS Config sent it
  (`AsyncEventsDropped`), because AWS Config then keeps showing the last results. It stays in `OK`
  if you don't deploy the Lambda rule.

The script also warns if no AWS CloudTrail trail is logging write management events including
global service events (the delegated administrator and self-monitoring rules need one), if `REGION`
isn't `us-east-1` or `us-gov-west-1`, about any subscription that was confirmed by clicking the
email link (anyone with a copy of an alert can unsubscribe it), and about any subscription with a
filter policy (it can silently drop alerts). It accepts a `CONFIRM_URL` only if it is an
Amazon SNS link for this topic, and it stops if it can't read your caller identity.

Re-running the script makes changes that the self-monitoring rules report, so expect a few alert
emails after each run. The two self-monitoring rules also report any other change to AWS Config
rules and conformance packs or to CloudTrail trails in the account, not only changes to this
solution, so expect alerts when other teams deploy rules.

Limits of self-monitoring:

- The rules see changes made in `us-east-1`. CloudTrail trail changes made from another Region are
  delivered to Amazon EventBridge in that Region.
- An administrator who can delete both self-monitoring rules in quick succession still can.
- Actions that the organization resource policy delegates to a member account (for example,
  enabling or disabling a policy type) are logged in that member account, not in the management
  account, so these rules don't see them.
- Every alert and both alarms use one Amazon SNS topic. If the topic or its policy is removed,
  alerts fail and go to the dead-letter queue, and the alarms change state in the Amazon CloudWatch
  console but can't notify you. If the last subscription is removed, alerts are published but reach
  no one.

For stronger protection, restrict who can use the management account, and also forward these events
to a separate security account with a cross-account Amazon EventBridge rule, so that a second copy
of every alert is outside the management account.

After a self-monitoring alert, re-running the setup scripts restores the EventBridge rules and
their `OrgAlertsSNS` targets, the topic policy, the dead-letter queue's retention, encryption, and
access policy, the alarms, and the Lambda rule's code, inline role policy, and AWS Config rule. It
doesn't undo other changes: extra rule targets or subscriptions, other subscription or topic
attributes (for example, a subscription filter policy or a topic encryption key), a changed role
trust policy, attached managed policies or a permissions boundary on
the role, changed function settings (for example, timeout, environment, or reserved concurrency),
or an extra or modified invoke permission. Review those with `aws events list-targets-by-rule`,
`aws sns list-subscriptions-by-topic`, `aws iam get-role`, `aws iam list-attached-role-policies`,
`aws lambda get-function-configuration`, `aws lambda get-function-concurrency`,
`aws lambda get-function-event-invoke-config`, `aws lambda get-function-url-config`, and
`aws lambda get-policy`, and revert anything you didn't change.

The optional `LAMBDA_FUNCTION_NAME` variable (default `orggov-required-policies-attached`) sets the
Lambda function and role names that the self-monitoring rule watches and that the
`OrgGovernanceLambdaRule-ErrorsOrThrottles` alarm monitors. If you deploy the Lambda rule with a
different `NAME`, set `LAMBDA_FUNCTION_NAME` to the same value.

### Step 3 (optional): Deploy the Lambda rule

See [Lambda rule example](#lambda-rule-example-required-policies-attached-to-every-ou).

## Verify

1. Check the conformance pack and rule results:

   ```bash
   aws configservice describe-conformance-pack-status --region us-east-1 \
     --conformance-pack-names organizations-control-plane-governance
   aws configservice describe-conformance-pack-compliance --region us-east-1 \
     --conformance-pack-name organizations-control-plane-governance \
     --query 'ConformancePackRuleComplianceList[].[ConfigRuleName,ComplianceType]' --output table
   ```

   Rules show `COMPLIANT`, `NON_COMPLIANT`, or `INSUFFICIENT_DATA` (no resources of that policy
   type exist in your organization). Non-compliant results are real findings for you to review.

2. Test the alerts with a change that has no effect on any account: create an SCP and leave it
   unattached, then edit it. Within a few minutes you receive an email with the configuration diff.
   The new policy is also reported as non-compliant by `policy-attached`. Delete the test policy
   afterwards.

   ```bash
   aws organizations create-policy --type SERVICE_CONTROL_POLICY --name orggov-alert-test \
     --description "Unattached test policy" \
     --content '{"Version":"2012-10-17","Statement":[{"Sid":"Test1","Effect":"Deny","Action":"s3:DeleteBucket","Resource":"*"}]}'
   aws organizations update-policy --policy-id <policy-id> \
     --content '{"Version":"2012-10-17","Statement":[{"Sid":"Test2","Effect":"Deny","Action":"s3:DeleteBucket","Resource":"*"}]}'
   aws organizations delete-policy --policy-id <policy-id>
   ```

## Explore the recorded data

List what AWS Config has discovered:

```bash
for T in Organization Account OrganizationalUnit Policy ResourcePolicy; do
  echo "== AWS::Organizations::$T =="
  aws configservice list-discovered-resources --region us-east-1 \
    --resource-type "AWS::Organizations::$T" \
    --query 'resourceIdentifiers[].{id:resourceId,name:resourceName}' --output table
done
```

Retrieve the full document of a policy:

```bash
aws configservice get-resource-config-history --region us-east-1 \
  --resource-type AWS::Organizations::Policy --resource-id <policy-id> \
  --limit 1 --query 'configurationItems[0].configuration' --output text | python3 -m json.tool
```

Find every account under an OU subtree with an advanced query. Each account configuration item
includes `Paths`, the full chain from the organization root:

```sql
SELECT resourceId, resourceName, configuration.Paths
WHERE resourceType = 'AWS::Organizations::Account'
  AND configuration.Paths LIKE 'o-exampleorgid/r-exmp/ou-exmp-workloads/%'
```

Show how a policy was configured on a given date (the newest configuration item recorded before it):

```bash
aws configservice get-resource-config-history --region us-east-1 \
  --resource-type AWS::Organizations::Policy --resource-id <policy-id> \
  --later-time 2026-06-30T23:59:59Z --limit 1
```

How far back you can look depends on the AWS Config
[retention period](https://docs.aws.amazon.com/config/latest/developerguide/delete-config-data-with-retention-period.html)
(default 7 years, configurable from 30 to 2,557 days). Check and set it to match your audit
requirements:

```bash
aws configservice describe-retention-configurations --region us-east-1
aws configservice put-retention-configuration --region us-east-1 --retention-period-in-days 2557
```

For evidence kept outside AWS Config, the delivery channel also writes configuration history files
for these resource types (`ConfigHistory_AWS::Organizations::*`) and snapshots to its Amazon S3
bucket. Retain them with your own S3 lifecycle rules and, if required, S3 Object Lock.

At the time of writing, `AWS::Organizations::Account` and `AWS::Organizations::ResourcePolicy` are
the AWS Organizations resource types available in advanced query; use `list-discovered-resources`
and `get-resource-config-history` for the others. Advanced query coverage grows over time, so check
the [supported resource types for advanced query](https://docs.aws.amazon.com/config/latest/developerguide/querying-AWS-resources.html#supported-resources) for the current list. Advanced query supports only suffix wildcards, so anchor `Paths`
matches at the root.

Investigate a change: in the AWS Config console, choose **Resources**, filter on a type such as
`AWS::Organizations::Account`, select the resource, and open the **Resource timeline**. An OU move
appears as a configuration change with a diff of `ParentIds` and `Paths`. The console timeline
shows camelCase keys; rules and the API use PascalCase. To find *who* made a change, look up the
AWS CloudTrail event by event name:

```bash
aws cloudtrail lookup-events --region us-east-1 \
  --lookup-attributes AttributeKey=EventName,AttributeValue=MoveAccount --max-results 20
```

## Rules

| Rule | Resource type | Checks |
|---|---|---|
| `org-feature-set-all` | Organization | Feature set equals `expectedFeatureSet` |
| `org-expected-management-account` | Organization | Management account equals `managementAccountId` |
| `account-not-at-root` | Account | Member accounts are not directly under the root |
| `account-approved-parent-ou` | Account | Accounts tagged `purpose=<tagValue>` are under the approved OU subtree |
| `account-required-owner-tag` | Account | `owner` tag present and not empty |
| `account-email-domain` | Account | Root-user email on the approved domain |
| `ou-max-depth` | OrganizationalUnit | At most 3 OU levels below the root |
| `scp-no-allow-star` | Policy (SCP) | No `Allow` with `Action "*"` in customer-managed SCPs |
| `scp-custom-not-on-root` | Policy (SCP) | Customer-managed SCPs not attached at the root |
| `rcp-deny-uses-org-condition` | Policy (RCP) | `Deny` statements scoped with `aws:PrincipalOrgID` |
| `policy-attached` | Policy | Customer-managed policies are attached somewhere |
| `s3-policy-bpa-all` | Policy ([Amazon S3](https://aws.amazon.com/s3/)) | Block Public Access `all` |
| `ec2-declarative-secure-values` | Policy ([Amazon EC2](https://aws.amazon.com/ec2/)) | VPC BPA not `off`; image/snapshot BPA on; serial console off; IMDSv2 required; Allowed AMIs active; VPC encryption managed |
| `guardduty-foundational-enabled` | Policy ([Amazon GuardDuty](https://aws.amazon.com/guardduty/)) | Foundational detection enabled in every enablement block |
| `securityhub-all-regions` | Policy ([AWS Security Hub](https://aws.amazon.com/security-hub/)) | `ALL_SUPPORTED` enabled; no Region disabled |
| `inspector-required-scans` | Policy (Amazon Inspector) | Amazon EC2, [Amazon Elastic Container Registry (Amazon ECR)](https://aws.amazon.com/ecr/), and AWS Lambda standard scanning in `ALL_SUPPORTED`; none disabled |
| `security-services-child-locked` | Policy (AWS Security Hub/Amazon Inspector at root) | Region lists locked against child policies (`@@none`) |
| `bedrock-guardrail-enforcement` | Policy ([Amazon Bedrock](https://aws.amazon.com/bedrock/)) | Guardrail owned by the management account, numeric version, `comprehensive` content guarding, no model exclusions |
| `ai-optout-all-services` | Policy (AI opt-out) | `default: optOut`; no service opted in |
| `backup-plan-minimums` | Policy ([AWS Backup](https://aws.amazon.com/backup/)) | Schedule, retention ≥ 35 days, and `copy_actions` on every rule |
| `upgrade-rollout-safe-order` | Policy (Upgrade rollout) | Explicit default patch order; production never `first` |
| `tag-policy-well-formed` | Policy (Tag) | `tag_key` set; enforced tags define allowed values |
| `chat-apps-restricted` | Policy (Chat applications) | Disabled by default; allowlists when enabled; no `channel_role` |
| `org-resource-policy-review` | ResourcePolicy | Informational: tag `reviewed=true` after reviewing (content is redacted in AWS Config) |

### What these rules can't check

Guard rules evaluate one configuration item at a time and are triggered by configuration changes.
Use AWS Lambda custom rules for checks that need inheritance (effective policies via
`DescribeEffectivePolicy`), cross-resource coverage (for example, every OU has a required SCP),
missing or deleted policies, API data (delegated administrators, Amazon Bedrock guardrail content),
or a schedule. A detached policy is still visible to Guard, because its `TargetIds` change.

## Lambda rule example: required policies attached to every OU

[`lambda-rules/required-policies-attached/`](lambda-rules/required-policies-attached/) checks that a
set of required organization policies (any type: SCP, RCP, or declarative) reaches every OU in
scope. A policy counts when it is attached to the OU, to a parent OU, or to the root. Each OU gets
one result; non-compliant OUs list the missing policies by name, ID, and type.

```bash
cd lambda-rules/required-policies-attached
python3 test_index.py                                     # 16 unit tests, no AWS calls
REQUIRED_POLICY_IDS="p-exampleid111,p-exampleid222" ./deploy.sh
REQUIRED_POLICY_IDS="p-exampleid111" TARGET_OU_IDS="ou-exmp-11112222" EXCLUDED_OU_IDS="ou-exmp-33334444" ./deploy.sh
```

Before it changes anything, `deploy.sh` checks the format of every ID and confirms that each
policy and OU exists, so a typo fails the deployment instead of producing misleading results. It
then creates, in the management account in `us-east-1`:

- Amazon CloudWatch Logs log group `/aws/lambda/orggov-required-policies-attached` with a
  retention period (`LOG_RETENTION_DAYS`, default 90).
- IAM role `orggov-required-policies-attached` allowing only `organizations:ListRoots`,
  `organizations:ListOrganizationalUnitsForParent`, `organizations:ListPoliciesForTarget`,
  `organizations:DescribePolicy`, `config:PutEvaluations`, and writing log events to its own log
  group.
- Lambda function `orggov-required-policies-attached` (Python 3.13), invocable only by AWS Config
  from your account.
- AWS Config rule `orggov-required-policies-attached`, triggered by configuration changes to
  `AWS::Organizations::OrganizationalUnit` and `AWS::Organizations::Policy` (attach, detach, and
  OU moves), plus a periodic run (`FREQUENCY`, default `TwentyFour_Hours`).

Parameters are comma-separated strings, so they work in the AWS Config console as well. If you
edit them later, the function logs any `targetOuIds` or `excludedOuIds` that don't exist (for
example, a deleted OU), and fails the evaluation if none of the `targetOuIds` exist. If a required
policy is deleted, every OU in scope is reported `NON_COMPLIANT` with the missing policy ID, so the
deletion shows up as a finding instead of a failed evaluation. Other failures (for example, missing
permissions) fail the evaluation, and the `OrgGovernanceLambdaRule-ErrorsOrThrottles` alarm from
the alerting script notifies you, because AWS Config keeps showing the last results until the next
successful evaluation.

## Using an AWS Config delegated administrator

- **Inventory:** a delegated administrator for `config.amazonaws.com` can use an organization
  aggregator that includes `us-east-1` to list all five AWS Organizations types, read full policy
  documents (`get-aggregate-resource-config`), and run the account-placement advanced query
  (`select-aggregate-resource-config`). Configuration history and the resource timeline remain in
  the management account.
- **Organization conformance pack from the delegated administrator** (`config-multiaccountsetup.amazonaws.com`):
  create the `AWSServiceRoleForConfigMultiAccountSetup` service-linked role in the management
  account (not created automatically; without it the pack isn't deployed there), deploy in
  `us-east-1`, expect copies of the rules in every account (they evaluate nothing outside the
  management account but count toward rule quotas; list accounts in `ExcludedAccounts` to skip
  them), ensure every account has a recorder in `us-east-1` (for a new account, deployment is
  retried for only 7 hours), and grant `organizations:ListDelegatedAdministrators`. Packs deployed from the
  management account and from the delegated administrator aren't visible to each other.
- **Lambda rule and alerts:** host the Lambda rule where it can read the organization tree, and
  forward the management account's AWS Config change events to the delegated administrator with a
  cross-account Amazon EventBridge rule if alerts should arrive there.

## Testing and writing rules

```bash
python3 tests/run_tests.py        # summary
python3 tests/run_tests.py -v     # every case
```

**Local tests are necessary but not sufficient.** AWS Config runs Guard **2.x**; the cfn-guard CLI
you install may be 3.x, and some constructs behave differently (for example, `some` combined with
wildcards). After changing a rule, deploy it (Option B with `DEBUG_LOGS=true`) and confirm both a
compliant and a non-compliant resource in AWS Config. Unattached AWS Organizations policies with
known content are safe test fixtures, because they have no effect on any account.

Guard authoring tips for these rules:

- Start each rule file with a `# Description:` comment line. `deploy-guard-rules.sh` and
  `build-conformance-pack.py` use it as the AWS Config rule description (256 characters at most,
  including the suffix that `deploy-guard-rules.sh` adds to rules with parameters).
- Read rule parameters with `CONFIG_RULE_PARAMETERS.<key>`.
- `empty` is true for a missing key, so check `exists` first.
- Regular expressions are literal; write `/` as `\x2F`.
- AWS Backup policy numbers are strings, so compare them with a regular expression.
- List parameters entered in the AWS Config console are stored as strings; these rules use only
  single-value parameters.
- Field names use the API casing (`ParentIds`, `Paths`), not the camelCase shown in the console
  resource timeline.

## Limits

- The conformance pack template is about 42 KB, under the 51,200-byte `--template-body` limit. If
  you add rules and exceed it, upload the template to an Amazon S3 bucket in the same Region and
  use `--template-s3-uri` (up to 300 KB). See
  [PutConformancePack](https://docs.aws.amazon.com/config/latest/APIReference/API_PutConformancePack.html).
- A conformance pack can contain up to 130 rules, and pack rules count toward the per-Region rule
  quota. See [AWS Config Service Limits](https://docs.aws.amazon.com/config/latest/developerguide/configlimits.html).
- Guard custom policy rules can't run on a schedule; they evaluate on configuration changes.
- For the limits of the alerts and self-monitoring, see [Step 2: Deploy the alerts](#step-2-deploy-the-alerts).

## Clean up

All commands run in the management account in `us-east-1`.

```bash
# Conformance pack
aws configservice delete-conformance-pack --region us-east-1 \
  --conformance-pack-name organizations-control-plane-governance

# Standalone rules (if deployed with deploy-guard-rules.sh) and the Lambda rule's AWS Config rule.
# Set PREFIX to the prefix you deployed with, then review the list and remove any rule that you
# didn't create with this sample before you delete.
PREFIX=orggov-
aws configservice describe-config-rules --region us-east-1 \
  --query "ConfigRules[?starts_with(ConfigRuleName,'${PREFIX}')].ConfigRuleName" --output text \
  | tr '\t' '\n' > rules-to-delete.txt
cat rules-to-delete.txt
xargs -n1 aws configservice delete-config-rule --region us-east-1 --config-rule-name < rules-to-delete.txt
rm rules-to-delete.txt

# Lambda rule example
aws lambda delete-function --region us-east-1 --function-name orggov-required-policies-attached
aws iam delete-role-policy --role-name orggov-required-policies-attached \
  --policy-name orggov-required-policies-attached-permissions
aws iam delete-role --role-name orggov-required-policies-attached
aws logs delete-log-group --region us-east-1 --log-group-name /aws/lambda/orggov-required-policies-attached

# Alerts (each deletion is reported until the self-monitoring rules are gone, so expect a few emails)
aws cloudwatch delete-alarms --region us-east-1 \
  --alarm-names OrgControlPlaneChangeAlerts-DLQ-NotEmpty OrgGovernanceLambdaRule-ErrorsOrThrottles
for R in OrgGovernanceSelfMonitoring OrgGovernanceAlertingSelfMonitoring \
         OrgControlPlaneConfigChanges OrgControlPlaneConfigChangesOversized OrgDelegatedAdminChanges; do
  aws events remove-targets --region us-east-1 --rule "$R" --ids OrgAlertsSNS
  aws events delete-rule --region us-east-1 --name "$R"
done
aws sns delete-topic --region us-east-1 --topic-arn "$(aws sns list-topics --region us-east-1 \
  --query "Topics[?ends_with(TopicArn,':OrgControlPlaneChangeAlerts')].TopicArn" --output text)"
aws sqs delete-queue --region us-east-1 --queue-url \
  "$(aws sqs get-queue-url --region us-east-1 --queue-name OrgControlPlaneChangeAlerts-DLQ --query QueueUrl --output text)"
```

Guard rule debug log groups under `/aws/config/config-rule/` are retained; delete them in Amazon
CloudWatch Logs if you no longer need them. If you changed the AWS Config recorder for this solution, revert
it as needed.

## Security

This solution reads configuration data that AWS Config already records and sends notifications. It
doesn't modify your organization, accounts, or policies.

- **Least privilege:** the Lambda rule's IAM role allows only the read-only AWS Organizations
  actions it needs, `config:PutEvaluations`, and writing log events to its own log group. The
  function can be invoked only by AWS Config from your account. The AWS Organizations read actions
  and `config:PutEvaluations` use `"Resource": "*"`: `organizations:ListRoots` and
  `config:PutEvaluations` don't support resource-level permissions, and the function reads every
  in-scope OU and its attached policies in the one organization that the management account
  belongs to. To scope `ListOrganizationalUnitsForParent`, `ListPoliciesForTarget`, and
  `DescribePolicy` further, use root, OU, and policy ARNs (see
  [Actions, resources, and condition keys for AWS Organizations](https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsorganizations.html)).
- **Notifications:** the Amazon SNS topic policy allows Amazon EventBridge in your account, and the
  two alarms that the script creates, to publish. IAM principals in your account whose identity
  policies allow `sns:Publish` can also publish, so restrict that permission. Subscriptions
  confirmed through the script require AWS authentication to unsubscribe. Alert emails contain
  organization data such as account IDs, account emails, policy content, and, for delegated
  administrator, trusted access, and self-monitoring alerts, the caller ARN and source IP address.
  Send them only to a distribution list that is allowed to see that data.
- **Encryption:** the Amazon SQS dead-letter queue uses SQS-managed server-side encryption. The
  script doesn't enable server-side encryption on the Amazon SNS topic. If your standards require
  it, set `KmsMasterKeyId` on the topic to a customer managed AWS KMS key whose key policy allows
  Amazon EventBridge (`events.amazonaws.com`) and Amazon CloudWatch (`cloudwatch.amazonaws.com`) to
  use `kms:GenerateDataKey*` and `kms:Decrypt` (see
  [Amazon SNS server-side encryption](https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html)).
  The key then becomes part of the alert path: if it is disabled, scheduled for deletion, or its key
  policy changes, alerts can't be delivered. The self-monitoring rules don't watch AWS KMS, so add
  an Amazon EventBridge rule for `DisableKey`, `ScheduleKeyDeletion`, and `PutKeyPolicy` on that key.
- **Protecting the solution itself:** the solution runs in the management account, and
  [SCPs don't affect users or roles in the management account](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html).
  Limit who can use the management account, and restrict changes to the AWS Config recorder and
  rules, the Amazon EventBridge rules, the Amazon SNS topic and subscriptions, the dead-letter queue,
  the alarms, and the Lambda function with IAM policies. The self-monitoring rules report changes to
  these resources.
- **Your responsibilities:** review the rules and alert recipients against your standards, keep an
  AWS CloudTrail trail for management events, use short-lived, least-privilege credentials to run
  the scripts, and test in a non-production organization first.

For more information, see the [AWS Shared Responsibility Model](https://aws.amazon.com/compliance/shared-responsibility-model/).
See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for security issue notifications.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.

## References

- [Recording AWS resources with AWS Config](https://docs.aws.amazon.com/config/latest/developerguide/select-resources.html)
- [AWS Config custom policy rules (Guard)](https://docs.aws.amazon.com/config/latest/developerguide/evaluate-config_develop-rules_cfn-guard.html)
- [AWS Config conformance packs](https://docs.aws.amazon.com/config/latest/developerguide/conformance-packs.html)
- [AWS CloudFormation Guard User Guide](https://docs.aws.amazon.com/cfn-guard/latest/ug/what-is-guard.html)
- [Managing organization policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies.html)
- [Monitoring AWS Config with Amazon EventBridge](https://docs.aws.amazon.com/config/latest/developerguide/monitor-config-with-cloudwatchevents.html)
- [AWS Config Service Limits](https://docs.aws.amazon.com/config/latest/developerguide/configlimits.html)
