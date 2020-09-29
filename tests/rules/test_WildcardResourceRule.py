import pytest

from cfripper.model.result import Failure
from cfripper.rules.wildcard_resource_rule import WildcardResourceRule
from tests.utils import compare_lists_of_failures, get_cfmodel_from


@pytest.fixture()
def user_with_wildcard_resource():
    return get_cfmodel_from("rules/WildcardResourceRule/iam_user_with_wildcard_resource.json").resolve()


@pytest.fixture()
def kms_key_with_wildcard_policy():
    return get_cfmodel_from("rules/WildcardResourceRule/kms_key_with_wildcard_resource.json").resolve()


@pytest.fixture()
def iam_policy_with_wildcard_resource_and_wildcard_action():
    return get_cfmodel_from(
        "rules/WildcardResourceRule/iam_policy_with_wildcard_resource_and_wildcard_action.json"
    ).resolve()


@pytest.fixture()
def iam_policy_with_wildcard_resource_without_policy_name():
    return get_cfmodel_from(
        "rules/WildcardResourceRule/iam_policy_with_wildcard_resource_without_policy_name.json"
    ).resolve()


@pytest.fixture()
def iam_policy_with_wildcard_resource_and_wilcard_action_without_policy_name():
    return get_cfmodel_from(
        "rules/WildcardResourceRule/iam_policy_with_wildcard_resource_and_wilcard_action_without_policy_name.json"
    ).resolve()


@pytest.fixture()
def iam_policy_with_wildcard_resource_and_wildcard_action_and_condition():
    return get_cfmodel_from(
        "rules/WildcardResourceRule/iam_policy_with_wildcard_resource_and_wildcard_action_and_condition.json"
    ).resolve()


@pytest.fixture()
def user_and_policy_with_wildcard_resource():
    return get_cfmodel_from("rules/WildcardResourceRule/multiple_resources_with_wildcard_resources.json").resolve()


def test_user_with_inline_policy_with_wildcard_resource_is_detected(user_with_wildcard_resource):
    rule = WildcardResourceRule(None)
    rule._config.stack_name = "not_whitelisted_stack"
    rule.all_cf_actions = set()
    result = rule.invoke(user_with_wildcard_resource)

    assert result.valid is False
    assert compare_lists_of_failures(
        result.failed_rules,
        [
            Failure(
                granularity="ACTION",
                reason='"userWithInline" is using a wildcard resource in "somePolicy" for "s3:DeleteBucket"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={"s3:ListBucket", "s3:DeleteBucket"},
                resource_ids={"userWithInline"},
            ),
            Failure(
                granularity="ACTION",
                reason='"userWithInline" is using a wildcard resource in "somePolicy" for "s3:ListBucket"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={"s3:ListBucket", "s3:DeleteBucket"},
                resource_ids={"userWithInline"},
            ),
        ],
    )


def test_kms_key_with_wildcard_resource_not_whitelisted_is_not_flagged(kms_key_with_wildcard_policy):
    # When KMS Key policies use * in the resource, that * will only apply this policy to the KMS Key being created
    # so we must not flag this
    # Source: https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html
    rule = WildcardResourceRule(None)
    rule._config.stack_name = "stack3"
    rule.all_cf_actions = set()
    result = rule.invoke(kms_key_with_wildcard_policy)

    assert result.valid
    assert result.failed_rules == []
    assert result.failed_monitored_rules == []


def test_policy_document_with_wildcard_resource_is_detected(iam_policy_with_wildcard_resource_and_wildcard_action):
    rule = WildcardResourceRule(None)
    rule._config.stack_name = "stack3"
    rule.all_cf_actions = set()
    result = rule.invoke(iam_policy_with_wildcard_resource_and_wildcard_action)

    assert result.valid is False
    assert compare_lists_of_failures(
        result.failed_rules,
        [
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "root" allowing all actions',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={"*"},
                resource_ids={"RolePolicy"},
            )
        ],
    )


def test_policy_document_with_condition_is_ignored(iam_policy_with_wildcard_resource_and_wildcard_action_and_condition):
    rule = WildcardResourceRule(None)
    rule._config.stack_name = "stack3"
    rule.all_cf_actions = set()
    result = rule.invoke(iam_policy_with_wildcard_resource_and_wildcard_action_and_condition)

    assert result.valid
    assert result.failed_monitored_rules == []
    assert compare_lists_of_failures(
        result.warnings,
        [
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "root" allowing all actions',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={"*"},
                resource_ids={"RolePolicy"},
            )
        ],
    )


def test_multiple_resources_with_wildcard_resources_are_detected(user_and_policy_with_wildcard_resource):
    rule = WildcardResourceRule(None)
    rule._config.stack_name = "stack3"
    rule.all_cf_actions = set()
    result = rule.invoke(user_and_policy_with_wildcard_resource)

    assert result.valid is False
    assert compare_lists_of_failures(
        result.failed_rules,
        [
            Failure(
                granularity="ACTION",
                reason='"userWithInline" is using a wildcard resource in "somePolicy" for "s3:DeleteBucket"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={"s3:ListBucket", "s3:DeleteBucket"},
                resource_ids={"userWithInline"},
            ),
            Failure(
                granularity="ACTION",
                reason='"userWithInline" is using a wildcard resource in "somePolicy" for "s3:ListBucket"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={"s3:ListBucket", "s3:DeleteBucket"},
                resource_ids={"userWithInline"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:BatchGetItem"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:CreateTable",
                    "dynamodb:BatchGet*",
                    "dynamodb:Scan",
                    "dynamodb:Update*",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:PutItem",
                    "dynamodb:DescribeStream",
                    "dynamodb:DescribeTable",
                    "dynamodb:BatchWrite*",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:BatchWriteItem"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:CreateTable",
                    "dynamodb:BatchGet*",
                    "dynamodb:Scan",
                    "dynamodb:Update*",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:PutItem",
                    "dynamodb:DescribeStream",
                    "dynamodb:DescribeTable",
                    "dynamodb:BatchWrite*",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:CreateTable"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:CreateTable",
                    "dynamodb:BatchGet*",
                    "dynamodb:Scan",
                    "dynamodb:Update*",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:PutItem",
                    "dynamodb:DescribeStream",
                    "dynamodb:DescribeTable",
                    "dynamodb:BatchWrite*",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:DeleteBackup"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:CreateTable",
                    "dynamodb:BatchGet*",
                    "dynamodb:Scan",
                    "dynamodb:Update*",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:PutItem",
                    "dynamodb:DescribeStream",
                    "dynamodb:DescribeTable",
                    "dynamodb:BatchWrite*",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:DeleteItem"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:CreateTable",
                    "dynamodb:BatchGet*",
                    "dynamodb:Scan",
                    "dynamodb:Update*",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:PutItem",
                    "dynamodb:DescribeStream",
                    "dynamodb:DescribeTable",
                    "dynamodb:BatchWrite*",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:DeleteTable"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:CreateTable",
                    "dynamodb:BatchGet*",
                    "dynamodb:Scan",
                    "dynamodb:Update*",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:PutItem",
                    "dynamodb:DescribeStream",
                    "dynamodb:DescribeTable",
                    "dynamodb:BatchWrite*",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:DeleteTableReplica"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:CreateTable",
                    "dynamodb:BatchGet*",
                    "dynamodb:Scan",
                    "dynamodb:Update*",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:PutItem",
                    "dynamodb:DescribeStream",
                    "dynamodb:DescribeTable",
                    "dynamodb:BatchWrite*",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:DescribeStream"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:CreateTable",
                    "dynamodb:BatchGet*",
                    "dynamodb:Scan",
                    "dynamodb:Update*",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:PutItem",
                    "dynamodb:DescribeStream",
                    "dynamodb:DescribeTable",
                    "dynamodb:BatchWrite*",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:DescribeTable"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:CreateTable",
                    "dynamodb:BatchGet*",
                    "dynamodb:Scan",
                    "dynamodb:Update*",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:PutItem",
                    "dynamodb:DescribeStream",
                    "dynamodb:DescribeTable",
                    "dynamodb:BatchWrite*",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:GetItem"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:CreateTable",
                    "dynamodb:BatchGet*",
                    "dynamodb:Scan",
                    "dynamodb:Update*",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:PutItem",
                    "dynamodb:DescribeStream",
                    "dynamodb:DescribeTable",
                    "dynamodb:BatchWrite*",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:GetRecords"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:CreateTable",
                    "dynamodb:BatchGet*",
                    "dynamodb:Scan",
                    "dynamodb:Update*",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:PutItem",
                    "dynamodb:DescribeStream",
                    "dynamodb:DescribeTable",
                    "dynamodb:BatchWrite*",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:GetShardIterator"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:CreateTable",
                    "dynamodb:BatchGet*",
                    "dynamodb:Scan",
                    "dynamodb:Update*",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:PutItem",
                    "dynamodb:DescribeStream",
                    "dynamodb:DescribeTable",
                    "dynamodb:BatchWrite*",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:PutItem"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:CreateTable",
                    "dynamodb:BatchGet*",
                    "dynamodb:Scan",
                    "dynamodb:Update*",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:PutItem",
                    "dynamodb:DescribeStream",
                    "dynamodb:DescribeTable",
                    "dynamodb:BatchWrite*",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:Query"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:CreateTable",
                    "dynamodb:BatchGet*",
                    "dynamodb:Scan",
                    "dynamodb:Update*",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:PutItem",
                    "dynamodb:DescribeStream",
                    "dynamodb:DescribeTable",
                    "dynamodb:BatchWrite*",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:Scan"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:CreateTable",
                    "dynamodb:BatchGet*",
                    "dynamodb:Scan",
                    "dynamodb:Update*",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:PutItem",
                    "dynamodb:DescribeStream",
                    "dynamodb:DescribeTable",
                    "dynamodb:BatchWrite*",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:UpdateContinuousBackups"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:CreateTable",
                    "dynamodb:BatchGet*",
                    "dynamodb:Scan",
                    "dynamodb:Update*",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:PutItem",
                    "dynamodb:DescribeStream",
                    "dynamodb:DescribeTable",
                    "dynamodb:BatchWrite*",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:UpdateContributorInsights"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:CreateTable",
                    "dynamodb:BatchGet*",
                    "dynamodb:Scan",
                    "dynamodb:Update*",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:PutItem",
                    "dynamodb:DescribeStream",
                    "dynamodb:DescribeTable",
                    "dynamodb:BatchWrite*",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:UpdateGlobalTable"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:CreateTable",
                    "dynamodb:BatchGet*",
                    "dynamodb:Scan",
                    "dynamodb:Update*",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:PutItem",
                    "dynamodb:DescribeStream",
                    "dynamodb:DescribeTable",
                    "dynamodb:BatchWrite*",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:UpdateGlobalTableSettings"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:CreateTable",
                    "dynamodb:BatchGet*",
                    "dynamodb:Scan",
                    "dynamodb:Update*",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:PutItem",
                    "dynamodb:DescribeStream",
                    "dynamodb:DescribeTable",
                    "dynamodb:BatchWrite*",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:UpdateItem"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:CreateTable",
                    "dynamodb:BatchGet*",
                    "dynamodb:Scan",
                    "dynamodb:Update*",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:PutItem",
                    "dynamodb:DescribeStream",
                    "dynamodb:DescribeTable",
                    "dynamodb:BatchWrite*",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:UpdateTable"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:CreateTable",
                    "dynamodb:BatchGet*",
                    "dynamodb:Scan",
                    "dynamodb:Update*",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:PutItem",
                    "dynamodb:DescribeStream",
                    "dynamodb:DescribeTable",
                    "dynamodb:BatchWrite*",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:UpdateTableReplicaAutoScaling"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:CreateTable",
                    "dynamodb:BatchGet*",
                    "dynamodb:Scan",
                    "dynamodb:Update*",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:PutItem",
                    "dynamodb:DescribeStream",
                    "dynamodb:DescribeTable",
                    "dynamodb:BatchWrite*",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:UpdateTimeToLive"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:CreateTable",
                    "dynamodb:BatchGet*",
                    "dynamodb:Scan",
                    "dynamodb:Update*",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:PutItem",
                    "dynamodb:DescribeStream",
                    "dynamodb:DescribeTable",
                    "dynamodb:BatchWrite*",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
            ),
        ],
    )


def test_policy_document_with_wildcard_resource_without_policy_name_is_detected(
    iam_policy_with_wildcard_resource_without_policy_name,
):
    rule = WildcardResourceRule(None)
    rule._config.stack_name = "stack3"
    rule.all_cf_actions = set()
    result = rule.invoke(iam_policy_with_wildcard_resource_without_policy_name)

    assert result.valid is False
    assert compare_lists_of_failures(
        result.failed_rules,
        [
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource for "sqs:AddPermission"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={"sqs:*"},
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource for "sqs:ChangeMessageVisibility"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={"sqs:*"},
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource for "sqs:ChangeMessageVisibilityBatch"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={"sqs:*"},
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource for "sqs:CreateQueue"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={"sqs:*"},
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource for "sqs:DeleteMessage"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={"sqs:*"},
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource for "sqs:DeleteMessageBatch"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={"sqs:*"},
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource for "sqs:DeleteQueue"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={"sqs:*"},
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource for "sqs:GetQueueAttributes"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={"sqs:*"},
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource for "sqs:GetQueueUrl"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={"sqs:*"},
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource for "sqs:ListDeadLetterSourceQueues"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={"sqs:*"},
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource for "sqs:ListQueueTags"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={"sqs:*"},
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource for "sqs:ListQueues"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={"sqs:*"},
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource for "sqs:PurgeQueue"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={"sqs:*"},
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource for "sqs:ReceiveMessage"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={"sqs:*"},
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource for "sqs:RemovePermission"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={"sqs:*"},
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource for "sqs:SendMessage"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={"sqs:*"},
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource for "sqs:SendMessageBatch"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={"sqs:*"},
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource for "sqs:SetQueueAttributes"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={"sqs:*"},
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource for "sqs:TagQueue"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={"sqs:*"},
                resource_ids={"RolePolicy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource for "sqs:UntagQueue"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={"sqs:*"},
                resource_ids={"RolePolicy"},
            ),
        ],
    )


def test_policy_document_with_wildcard_resource_and_wilcard_action_without_policy_name_is_detected(
    iam_policy_with_wildcard_resource_and_wilcard_action_without_policy_name,
):
    rule = WildcardResourceRule(None)
    rule._config.stack_name = "stack3"
    rule.all_cf_actions = set()
    result = rule.invoke(iam_policy_with_wildcard_resource_and_wilcard_action_without_policy_name)

    assert result.valid is False
    assert compare_lists_of_failures(
        result.failed_rules,
        [
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource allowing all actions',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={"*"},
                resource_ids={"RolePolicy"},
            )
        ],
    )
