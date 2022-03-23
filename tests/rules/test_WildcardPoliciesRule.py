from unittest.mock import patch

import pytest

from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rules.wildcard_policies import (
    GenericWildcardPolicyRule,
    S3BucketPolicyWildcardActionRule,
    SNSTopicPolicyWildcardActionRule,
    SQSQueuePolicyWildcardActionRule,
)
from tests.utils import compare_lists_of_failures, get_cfmodel_from


@pytest.fixture()
def s3_bucket_with_wildcards():
    return get_cfmodel_from("rules/WildcardPoliciesRule/s3_bucket_with_wildcards.json").resolve()


@pytest.fixture()
def sqs_queue_with_wildcards():
    return get_cfmodel_from("rules/WildcardPoliciesRule/sqs_queue_with_wildcards.json").resolve()


@pytest.fixture()
def sns_topic_with_wildcards():
    return get_cfmodel_from("rules/WildcardPoliciesRule/sns_topic_with_wildcards.json").resolve()


@patch("cfripper.rules.wildcard_policies.logger.warning")
def test_invoking_general_rule_not_allowed(mock_logger, s3_bucket_with_wildcards):
    rule = GenericWildcardPolicyRule(None)
    result = rule.invoke(s3_bucket_with_wildcards)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])

    mock_logger.assert_called_once_with("Not running GenericWildcardPolicyRule rule as AWS_RESOURCE is not defined.")


def test_s3_bucket_with_wildcards(s3_bucket_with_wildcards):
    rule = S3BucketPolicyWildcardActionRule(None)
    result = rule.invoke(s3_bucket_with_wildcards)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="The S3BucketPolicy S3BucketPolicy should not allow a `*` action",
                risk_value=RuleRisk.MEDIUM,
                rule="S3BucketPolicyWildcardActionRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"S3BucketPolicy"},
                resource_types={"AWS::S3::BucketPolicy"},
            ),
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="The S3BucketPolicy S3BucketPolicy2 should not allow a `*` action",
                risk_value=RuleRisk.MEDIUM,
                rule="S3BucketPolicyWildcardActionRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"S3BucketPolicy2"},
                resource_types={"AWS::S3::BucketPolicy"},
            ),
        ],
    )


def test_sqs_queue_with_wildcards(sqs_queue_with_wildcards):
    rule = SQSQueuePolicyWildcardActionRule(None)
    result = rule.invoke(sqs_queue_with_wildcards)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="The SQSQueuePolicy mysqspolicy1 should not allow a `*` action",
                risk_value=RuleRisk.MEDIUM,
                rule="SQSQueuePolicyWildcardActionRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"mysqspolicy1"},
                resource_types={"AWS::SQS::QueuePolicy"},
            ),
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="The SQSQueuePolicy mysqspolicy1b should not allow a `*` action",
                risk_value=RuleRisk.MEDIUM,
                rule="SQSQueuePolicyWildcardActionRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"mysqspolicy1b"},
                resource_types={"AWS::SQS::QueuePolicy"},
            ),
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="The SQSQueuePolicy mysqspolicy1c should not allow a `*` action",
                risk_value=RuleRisk.MEDIUM,
                rule="SQSQueuePolicyWildcardActionRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"mysqspolicy1c"},
                resource_types={"AWS::SQS::QueuePolicy"},
            ),
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="The SQSQueuePolicy mysqspolicy1d should not allow a `*` action",
                risk_value=RuleRisk.MEDIUM,
                rule="SQSQueuePolicyWildcardActionRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"mysqspolicy1d"},
                resource_types={"AWS::SQS::QueuePolicy"},
            ),
        ],
    )


def test_sns_topic_with_wildcards(sns_topic_with_wildcards):
    rule = SNSTopicPolicyWildcardActionRule(None)
    result = rule.invoke(sns_topic_with_wildcards)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="The SNSTopicPolicy mysnspolicy1 should not allow a `*` action",
                risk_value=RuleRisk.MEDIUM,
                rule="SNSTopicPolicyWildcardActionRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"mysnspolicy1"},
                resource_types={"AWS::SNS::TopicPolicy"},
            )
        ],
    )


def test_rule_supports_filter_config(sns_topic_with_wildcards, default_allow_all_config):
    rule = SNSTopicPolicyWildcardActionRule(default_allow_all_config)
    result = rule.invoke(sns_topic_with_wildcards)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])
