from unittest.mock import patch

import pydantic
import pytest
from pycfmodel.model.resources.iam_policy import IAMPolicy

from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rules.wildcard_resource_rule import WildcardResourceRule
from tests.utils import compare_lists_of_failures, get_cfmodel_from


@pytest.fixture()
def user_with_wildcard_resource():
    return get_cfmodel_from("rules/WildcardResourceRule/iam_user_with_wildcard_resource.json").resolve()


@pytest.fixture()
def kms_key_with_wildcard_policy():
    return get_cfmodel_from("rules/KMSKeyWildcardPrincipalRule/kms_key_with_wildcard_resource.json").resolve()


@pytest.fixture()
def iam_policy_with_wildcard_resource_and_wildcard_action():
    return get_cfmodel_from(
        "rules/WildcardResourceRule/iam_policy_with_wildcard_resource_and_wildcard_action.json"
    ).resolve()


@pytest.fixture()
def iam_policy_with_wildcard_resource_and_wildcard_action_and_condition():
    return get_cfmodel_from(
        "rules/WildcardResourceRule/iam_policy_with_wildcard_resource_and_wildcard_action_and_condition.json"
    ).resolve()


@pytest.fixture()
def policy_with_s3_wildcard_and_all_buckets():
    model = get_cfmodel_from("rules/WildcardResourceRule/policy_with_s3_wildcard_and_all_buckets.json")
    return model.resolve()


@pytest.fixture()
def user_and_policy_with_wildcard_resource():
    return get_cfmodel_from("rules/WildcardResourceRule/multiple_resources_with_wildcard_resources.json").resolve()


@pytest.fixture()
def policy_with_string_policy_document():
    return get_cfmodel_from("rules/WildcardResourceRule/policy_with_string_policy_document.json").resolve()


@pytest.fixture()
def policy_with_invalid_string_policy_document():
    return get_cfmodel_from("rules/WildcardResourceRule/policy_with_invalid_string_policy_document.json").resolve()


def test_user_with_inline_policy_with_wildcard_resource_is_detected(user_with_wildcard_resource):
    rule = WildcardResourceRule(None)
    rule._config.stack_name = "not_allowed_stack"
    rule.all_cf_actions = set()
    result = rule.invoke(user_with_wildcard_resource)

    assert result.valid is False
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity="ACTION",
                reason='"userWithInline" is using a wildcard resource in "somePolicy" for "s3:DeleteBucket"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={"s3:ListBucket", "s3:DeleteBucket"},
                resource_ids={"userWithInline"},
                resource_types={"AWS::IAM::User"},
            ),
            Failure(
                granularity="ACTION",
                reason='"userWithInline" is using a wildcard resource in "somePolicy" for "s3:ListBucket"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={"s3:ListBucket", "s3:DeleteBucket"},
                resource_ids={"userWithInline"},
                resource_types={"AWS::IAM::User"},
            ),
        ],
    )


def test_kms_key_with_wildcard_resource_not_allowed_is_not_flagged(kms_key_with_wildcard_policy):
    # When KMS Key policies use * in the resource, that * will only apply this policy to the KMS Key being created
    # so, we must not flag this
    # Source: https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html
    rule = WildcardResourceRule(None)
    rule._config.stack_name = "stack3"
    rule.all_cf_actions = set()
    result = rule.invoke(kms_key_with_wildcard_policy)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_exclude_certain_resources_on_rule(iam_policy_with_wildcard_resource_and_wildcard_action):
    # Any subclass of this rule may want to exclude certain resource types. As a test, let's exclude IAM Policies.
    rule = WildcardResourceRule(None)
    rule._config.stack_name = "stack3"
    rule.all_cf_actions = set()
    rule.EXCLUDED_RESOURCE_TYPES = (IAMPolicy,)
    result = rule.invoke(iam_policy_with_wildcard_resource_and_wildcard_action)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_policy_document_with_wildcard_resource_is_detected(iam_policy_with_wildcard_resource_and_wildcard_action):
    rule = WildcardResourceRule(None)
    rule._config.stack_name = "stack3"
    rule.all_cf_actions = set()
    result = rule.invoke(iam_policy_with_wildcard_resource_and_wildcard_action)

    assert result.valid is False
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "root" allowing all actions',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={"*"},
                resource_ids={"RolePolicy"},
                resource_types={"AWS::IAM::Policy"},
            )
        ],
    )


def test_policy_document_with_condition_is_ignored(iam_policy_with_wildcard_resource_and_wildcard_action_and_condition):
    rule = WildcardResourceRule(None)
    rule._config.stack_name = "stack3"
    rule.all_cf_actions = set()
    result = rule.invoke(iam_policy_with_wildcard_resource_and_wildcard_action_and_condition)

    assert result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.ACTION,
                reason='"RolePolicy" is using a wildcard resource in "root" allowing all actions',
                risk_value=RuleRisk.MEDIUM,
                rule="WildcardResourceRule",
                rule_mode=RuleMode.MONITOR,
                actions={"*"},
                resource_ids={"RolePolicy"},
                resource_types={"AWS::IAM::Policy"},
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
        result.failures,
        [
            Failure(
                granularity="ACTION",
                reason='"userWithInline" is using a wildcard resource in "somePolicy" for "s3:DeleteBucket"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={"s3:ListBucket", "s3:DeleteBucket"},
                resource_ids={"userWithInline"},
                resource_types={"AWS::IAM::User"},
            ),
            Failure(
                granularity="ACTION",
                reason='"userWithInline" is using a wildcard resource in "somePolicy" for "s3:ListBucket"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={"s3:ListBucket", "s3:DeleteBucket"},
                resource_ids={"userWithInline"},
                resource_types={"AWS::IAM::User"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:BatchGetItem"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:Update*",
                    "dynamodb:DescribeStream",
                    "dynamodb:BatchGet*",
                    "dynamodb:CreateTable",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:BatchWrite*",
                    "dynamodb:DescribeTable",
                    "dynamodb:Scan",
                    "dynamodb:PutItem",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
                resource_types={"AWS::IAM::Policy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:BatchWriteItem"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:Update*",
                    "dynamodb:DescribeStream",
                    "dynamodb:BatchGet*",
                    "dynamodb:CreateTable",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:BatchWrite*",
                    "dynamodb:DescribeTable",
                    "dynamodb:Scan",
                    "dynamodb:PutItem",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
                resource_types={"AWS::IAM::Policy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:CreateTable"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:Update*",
                    "dynamodb:DescribeStream",
                    "dynamodb:BatchGet*",
                    "dynamodb:CreateTable",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:BatchWrite*",
                    "dynamodb:DescribeTable",
                    "dynamodb:Scan",
                    "dynamodb:PutItem",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
                resource_types={"AWS::IAM::Policy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:DeleteBackup"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:Update*",
                    "dynamodb:DescribeStream",
                    "dynamodb:BatchGet*",
                    "dynamodb:CreateTable",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:BatchWrite*",
                    "dynamodb:DescribeTable",
                    "dynamodb:Scan",
                    "dynamodb:PutItem",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
                resource_types={"AWS::IAM::Policy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:DeleteItem"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:Update*",
                    "dynamodb:DescribeStream",
                    "dynamodb:BatchGet*",
                    "dynamodb:CreateTable",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:BatchWrite*",
                    "dynamodb:DescribeTable",
                    "dynamodb:Scan",
                    "dynamodb:PutItem",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
                resource_types={"AWS::IAM::Policy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:DeleteResourcePolicy"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:Update*",
                    "dynamodb:DescribeStream",
                    "dynamodb:BatchGet*",
                    "dynamodb:CreateTable",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:BatchWrite*",
                    "dynamodb:DescribeTable",
                    "dynamodb:Scan",
                    "dynamodb:PutItem",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
                resource_types={"AWS::IAM::Policy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:DeleteTable"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:Update*",
                    "dynamodb:DescribeStream",
                    "dynamodb:BatchGet*",
                    "dynamodb:CreateTable",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:BatchWrite*",
                    "dynamodb:DescribeTable",
                    "dynamodb:Scan",
                    "dynamodb:PutItem",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
                resource_types={"AWS::IAM::Policy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:DeleteTableReplica"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:Update*",
                    "dynamodb:DescribeStream",
                    "dynamodb:BatchGet*",
                    "dynamodb:CreateTable",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:BatchWrite*",
                    "dynamodb:DescribeTable",
                    "dynamodb:Scan",
                    "dynamodb:PutItem",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
                resource_types={"AWS::IAM::Policy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:DescribeStream"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:Update*",
                    "dynamodb:DescribeStream",
                    "dynamodb:BatchGet*",
                    "dynamodb:CreateTable",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:BatchWrite*",
                    "dynamodb:DescribeTable",
                    "dynamodb:Scan",
                    "dynamodb:PutItem",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
                resource_types={"AWS::IAM::Policy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:DescribeTable"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:Update*",
                    "dynamodb:DescribeStream",
                    "dynamodb:BatchGet*",
                    "dynamodb:CreateTable",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:BatchWrite*",
                    "dynamodb:DescribeTable",
                    "dynamodb:Scan",
                    "dynamodb:PutItem",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
                resource_types={"AWS::IAM::Policy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:GetItem"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:Update*",
                    "dynamodb:DescribeStream",
                    "dynamodb:BatchGet*",
                    "dynamodb:CreateTable",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:BatchWrite*",
                    "dynamodb:DescribeTable",
                    "dynamodb:Scan",
                    "dynamodb:PutItem",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
                resource_types={"AWS::IAM::Policy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:GetRecords"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:Update*",
                    "dynamodb:DescribeStream",
                    "dynamodb:BatchGet*",
                    "dynamodb:CreateTable",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:BatchWrite*",
                    "dynamodb:DescribeTable",
                    "dynamodb:Scan",
                    "dynamodb:PutItem",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
                resource_types={"AWS::IAM::Policy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:GetResourcePolicy"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:Update*",
                    "dynamodb:DescribeStream",
                    "dynamodb:BatchGet*",
                    "dynamodb:CreateTable",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:BatchWrite*",
                    "dynamodb:DescribeTable",
                    "dynamodb:Scan",
                    "dynamodb:PutItem",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
                resource_types={"AWS::IAM::Policy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:GetShardIterator"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:Update*",
                    "dynamodb:DescribeStream",
                    "dynamodb:BatchGet*",
                    "dynamodb:CreateTable",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:BatchWrite*",
                    "dynamodb:DescribeTable",
                    "dynamodb:Scan",
                    "dynamodb:PutItem",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
                resource_types={"AWS::IAM::Policy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:PutItem"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:Update*",
                    "dynamodb:DescribeStream",
                    "dynamodb:BatchGet*",
                    "dynamodb:CreateTable",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:BatchWrite*",
                    "dynamodb:DescribeTable",
                    "dynamodb:Scan",
                    "dynamodb:PutItem",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
                resource_types={"AWS::IAM::Policy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:Query"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:Update*",
                    "dynamodb:DescribeStream",
                    "dynamodb:BatchGet*",
                    "dynamodb:CreateTable",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:BatchWrite*",
                    "dynamodb:DescribeTable",
                    "dynamodb:Scan",
                    "dynamodb:PutItem",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
                resource_types={"AWS::IAM::Policy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:Scan"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:Update*",
                    "dynamodb:DescribeStream",
                    "dynamodb:BatchGet*",
                    "dynamodb:CreateTable",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:BatchWrite*",
                    "dynamodb:DescribeTable",
                    "dynamodb:Scan",
                    "dynamodb:PutItem",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
                resource_types={"AWS::IAM::Policy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:UpdateContinuousBackups"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:Update*",
                    "dynamodb:DescribeStream",
                    "dynamodb:BatchGet*",
                    "dynamodb:CreateTable",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:BatchWrite*",
                    "dynamodb:DescribeTable",
                    "dynamodb:Scan",
                    "dynamodb:PutItem",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
                resource_types={"AWS::IAM::Policy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:UpdateContributorInsights"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:Update*",
                    "dynamodb:DescribeStream",
                    "dynamodb:BatchGet*",
                    "dynamodb:CreateTable",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:BatchWrite*",
                    "dynamodb:DescribeTable",
                    "dynamodb:Scan",
                    "dynamodb:PutItem",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
                resource_types={"AWS::IAM::Policy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:UpdateGlobalTable"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:Update*",
                    "dynamodb:DescribeStream",
                    "dynamodb:BatchGet*",
                    "dynamodb:CreateTable",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:BatchWrite*",
                    "dynamodb:DescribeTable",
                    "dynamodb:Scan",
                    "dynamodb:PutItem",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
                resource_types={"AWS::IAM::Policy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:UpdateGlobalTableSettings"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:Update*",
                    "dynamodb:DescribeStream",
                    "dynamodb:BatchGet*",
                    "dynamodb:CreateTable",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:BatchWrite*",
                    "dynamodb:DescribeTable",
                    "dynamodb:Scan",
                    "dynamodb:PutItem",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
                resource_types={"AWS::IAM::Policy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:UpdateGlobalTableVersion"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:Update*",
                    "dynamodb:DescribeStream",
                    "dynamodb:BatchGet*",
                    "dynamodb:CreateTable",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:BatchWrite*",
                    "dynamodb:DescribeTable",
                    "dynamodb:Scan",
                    "dynamodb:PutItem",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
                resource_types={"AWS::IAM::Policy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:UpdateItem"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:Update*",
                    "dynamodb:DescribeStream",
                    "dynamodb:BatchGet*",
                    "dynamodb:CreateTable",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:BatchWrite*",
                    "dynamodb:DescribeTable",
                    "dynamodb:Scan",
                    "dynamodb:PutItem",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
                resource_types={"AWS::IAM::Policy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:UpdateKinesisStreamingDestination"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:Update*",
                    "dynamodb:DescribeStream",
                    "dynamodb:BatchGet*",
                    "dynamodb:CreateTable",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:BatchWrite*",
                    "dynamodb:DescribeTable",
                    "dynamodb:Scan",
                    "dynamodb:PutItem",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
                resource_types={"AWS::IAM::Policy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:UpdateTable"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:Update*",
                    "dynamodb:DescribeStream",
                    "dynamodb:BatchGet*",
                    "dynamodb:CreateTable",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:BatchWrite*",
                    "dynamodb:DescribeTable",
                    "dynamodb:Scan",
                    "dynamodb:PutItem",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
                resource_types={"AWS::IAM::Policy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:UpdateTableReplicaAutoScaling"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:Update*",
                    "dynamodb:DescribeStream",
                    "dynamodb:BatchGet*",
                    "dynamodb:CreateTable",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:BatchWrite*",
                    "dynamodb:DescribeTable",
                    "dynamodb:Scan",
                    "dynamodb:PutItem",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
                resource_types={"AWS::IAM::Policy"},
            ),
            Failure(
                granularity="ACTION",
                reason='"RolePolicy" is using a wildcard resource in "TheExtremePolicy" for "dynamodb:UpdateTimeToLive"',
                risk_value="MEDIUM",
                rule="WildcardResourceRule",
                rule_mode="BLOCKING",
                actions={
                    "dynamodb:Update*",
                    "dynamodb:DescribeStream",
                    "dynamodb:BatchGet*",
                    "dynamodb:CreateTable",
                    "dynamodb:Query",
                    "dynamodb:Delete*",
                    "dynamodb:BatchWrite*",
                    "dynamodb:DescribeTable",
                    "dynamodb:Scan",
                    "dynamodb:PutItem",
                    "dynamodb:Get*",
                },
                resource_ids={"RolePolicy"},
                resource_types={"AWS::IAM::Policy"},
            ),
        ],
    )


def test_policy_s3_wildcard_and_all_buckets(policy_with_s3_wildcard_and_all_buckets):
    rule = WildcardResourceRule(None)
    rule._config.stack_name = "stack3"
    rule.all_cf_actions = set()
    result = rule.invoke(policy_with_s3_wildcard_and_all_buckets)

    assert result.valid is False
    assert (
        Failure(
            granularity="ACTION",
            reason='"RolePolicy" is using a wildcard resource in "Policy for something." for "s3:PutObject"',
            risk_value="MEDIUM",
            rule="WildcardResourceRule",
            rule_mode="BLOCKING",
            actions={"s3:*"},
            resource_ids={"RolePolicy"},
            resource_types={"AWS::IAM::Policy"},
        )
        in result.failures
    )
    assert 100 < len(result.failures)


def test_policy_with_string_policy_document(policy_with_string_policy_document):
    rule = WildcardResourceRule(None)
    rule.all_cf_actions = set()
    result = rule.invoke(policy_with_string_policy_document)

    assert result.valid is False
    assert result.failures == [
        Failure(
            granularity="ACTION",
            reason='"GuardDutyResourcePolicy" is using a wildcard resource for "logs:CreateLogStream"',
            risk_value="MEDIUM",
            rule="WildcardResourceRule",
            rule_mode="BLOCKING",
            actions={"logs:CreateLogStream"},
            resource_ids={"GuardDutyResourcePolicy"},
            resource_types={"AWS::Logs::ResourcePolicy"},
        )
    ]


@patch("logging.Logger.warning")
def test_policy_with_invalid_string_policy_document(patched_logger, policy_with_invalid_string_policy_document):
    rule = WildcardResourceRule(None)
    rule.all_cf_actions = set()
    result = rule.invoke(policy_with_invalid_string_policy_document)

    assert result.valid is True
    patched_logger.assert_called_with(
        "Could not process the PolicyDocument FOOBARFOOBAR on GuardDutyResourcePolicy", stack_info=True
    )


def test_policy_document_with_wildcard_resource_without_policy_name_is_detected():
    with pytest.raises(pydantic.ValidationError):
        get_cfmodel_from("rules/WildcardResourceRule/iam_policy_with_wildcard_resource_without_policy_name.json")


def test_policy_document_with_wildcard_resource_and_wildcard_action_without_policy_name_is_detected():
    with pytest.raises(pydantic.ValidationError):
        get_cfmodel_from(
            "rules/WildcardResourceRule/iam_policy_with_wildcard_resource_and_wildcard_action_without_policy_name.json"
        )
