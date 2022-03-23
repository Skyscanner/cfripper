import pytest

from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rules import SQSQueuePolicyNotPrincipalRule
from tests.utils import compare_lists_of_failures, get_cfmodel_from


@pytest.fixture()
def sqs_policy_not_principal():
    return get_cfmodel_from("rules/SQSQueuePolicyNotPrincipalRule/bad_template.json").resolve()


def test_sqs_policy_not_principal(sqs_policy_not_principal):
    rule = SQSQueuePolicyNotPrincipalRule(None)
    result = rule.invoke(sqs_policy_not_principal)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="SQS Queue policy QueuePolicyWithNotPrincipal should not allow Allow and NotPrincipal at the same time",
                risk_value=RuleRisk.MEDIUM,
                rule="SQSQueuePolicyNotPrincipalRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"QueuePolicyWithNotPrincipal"},
                resource_types={"AWS::SQS::QueuePolicy"},
            )
        ],
    )


def test_rule_supports_filter_config(sqs_policy_not_principal, default_allow_all_config):
    rule = SQSQueuePolicyNotPrincipalRule(default_allow_all_config)
    result = rule.invoke(sqs_policy_not_principal)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])
