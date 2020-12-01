from pytest import fixture

from cfripper.model.enums import RuleRisk
from cfripper.rules.sqs_queue_policy import SQSDangerousPolicyActionsRule
from tests.utils import get_cfmodel_from


@fixture()
def sqs_policy():
    return get_cfmodel_from("rules/SQSDangerousPolicyActionsRule/sqs_policy.json").resolve()


def test_sqs_dangerous_policy_actions(sqs_policy):
    rule = SQSDangerousPolicyActionsRule(None)
    result = rule.invoke(sqs_policy)

    assert not result.valid
    assert len(result.failed_rules) == 4
    assert len(result.failed_monitored_rules) == 0
    assert result.failed_rules[0].risk_value == RuleRisk.MEDIUM
    assert result.failed_rules[0].rule == "SQSDangerousPolicyActionsRule"
    assert (
        result.failed_rules[0].reason
        == "SQS Queue policy QueuePolicyPublic1 should not not include the following dangerous actions: "
        "['sqs:AddPermission', 'sqs:CreateQueue', 'sqs:DeleteQueue', 'sqs:RemovePermission', 'sqs:TagQueue']"
    )
    assert result.failed_rules[1].rule == "SQSDangerousPolicyActionsRule"
    assert (
        result.failed_rules[1].reason
        == "SQS Queue policy QueuePolicyPublic2 should not not include the following dangerous actions: "
        "['sqs:AddPermission', 'sqs:CreateQueue', 'sqs:DeleteQueue', 'sqs:RemovePermission', 'sqs:TagQueue']"
    )
    assert result.failed_rules[2].rule == "SQSDangerousPolicyActionsRule"
    assert (
        result.failed_rules[2].reason
        == "SQS Queue policy QueuePolicyPublic3 should not not include the following dangerous actions: "
        "['sqs:AddPermission', 'sqs:CreateQueue', 'sqs:DeleteQueue', 'sqs:RemovePermission', 'sqs:TagQueue']"
    )
    assert result.failed_rules[3].rule == "SQSDangerousPolicyActionsRule"
    assert (
        result.failed_rules[3].reason
        == "SQS Queue policy QueuePolicyPublic4 should not not include the following dangerous actions: "
        "['sqs:AddPermission', 'sqs:CreateQueue', 'sqs:DeleteQueue', 'sqs:RemovePermission', 'sqs:TagQueue']"
    )
