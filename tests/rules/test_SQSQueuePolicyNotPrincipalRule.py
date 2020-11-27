import pytest

from cfripper.rules import SQSQueuePolicyNotPrincipalRule
from tests.utils import get_cfmodel_from


@pytest.fixture()
def sqs_policy_not_principal():
    return get_cfmodel_from("rules/SQSQueuePolicyNotPrincipalRule/bad_template.json").resolve()


def test_sqs_policy_not_principal(sqs_policy_not_principal):
    rule = SQSQueuePolicyNotPrincipalRule(None)
    result = rule.invoke(sqs_policy_not_principal)

    assert not result.valid
    assert len(result.failed_monitored_rules) == 0
    assert len(result.failed_rules) == 1
    assert result.failed_rules[0].rule == "SQSQueuePolicyNotPrincipalRule"
    assert (
        result.failed_rules[0].reason
        == "SQS Queue policy QueuePolicyWithNotPrincipal should not allow Allow and NotPrincipal at the same time"
    )
