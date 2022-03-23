import pytest

from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rules import SQSQueuePolicyPublicRule
from tests.utils import compare_lists_of_failures, get_cfmodel_from


@pytest.fixture()
def sqs_policy_public():
    return get_cfmodel_from("rules/SQSQueuePolicyPublicRule/sqs_policy_public.json").resolve()


def test_sqs_policy_public(sqs_policy_public):
    rule = SQSQueuePolicyPublicRule(None)
    result = rule.invoke(sqs_policy_public)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="SQS Queue policy QueuePolicyPublic1 should not be public",
                risk_value=RuleRisk.HIGH,
                rule="SQSQueuePolicyPublicRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"QueuePolicyPublic1"},
                resource_types={"AWS::SQS::QueuePolicy"},
            ),
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="SQS Queue policy QueuePolicyPublic2 should not be public",
                risk_value=RuleRisk.HIGH,
                rule="SQSQueuePolicyPublicRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"QueuePolicyPublic2"},
                resource_types={"AWS::SQS::QueuePolicy"},
            ),
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="SQS Queue policy QueuePolicyPublic3 should not be public",
                risk_value=RuleRisk.HIGH,
                rule="SQSQueuePolicyPublicRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"QueuePolicyPublic3"},
                resource_types={"AWS::SQS::QueuePolicy"},
            ),
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="SQS Queue policy QueuePolicyPublic4 should not be public",
                risk_value=RuleRisk.HIGH,
                rule="SQSQueuePolicyPublicRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"QueuePolicyPublic4"},
                resource_types={"AWS::SQS::QueuePolicy"},
            ),
        ],
    )


def test_rule_supports_filter_config(sqs_policy_public, default_allow_all_config):
    rule = SQSQueuePolicyPublicRule(default_allow_all_config)
    result = rule.invoke(sqs_policy_public)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])
