import pytest

from cfripper.model.enums import RuleRisk
from cfripper.rules import SQSQueuePolicyPublicRule
from tests.utils import get_cfmodel_from


@pytest.fixture()
def sqs_policy_public():
    return get_cfmodel_from("rules/SQSQueuePolicyPublicRule/sqs_policy_public.json").resolve()


def test_sqs_policy_public(sqs_policy_public):
    rule = SQSQueuePolicyPublicRule(None)
    result = rule.invoke(sqs_policy_public)

    assert not result.valid
    assert len(result.failed_rules) == 4
    assert len(result.failed_monitored_rules) == 0
    assert result.failed_rules[0].risk_value == RuleRisk.HIGH
    assert result.failed_rules[0].rule == "SQSQueuePolicyPublicRule"
    assert result.failed_rules[0].reason == "SQS Queue policy QueuePolicyPublic1 should not be public"
    assert result.failed_rules[1].rule == "SQSQueuePolicyPublicRule"
    assert result.failed_rules[1].reason == "SQS Queue policy QueuePolicyPublic2 should not be public"
    assert result.failed_rules[2].rule == "SQSQueuePolicyPublicRule"
    assert result.failed_rules[2].reason == "SQS Queue policy QueuePolicyPublic3 should not be public"
    assert result.failed_rules[3].rule == "SQSQueuePolicyPublicRule"
    assert result.failed_rules[3].reason == "SQS Queue policy QueuePolicyPublic4 should not be public"
