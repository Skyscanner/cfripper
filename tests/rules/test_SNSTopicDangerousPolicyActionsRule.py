from pytest import fixture

from cfripper.model.enums import RuleRisk
from cfripper.rules.sns_topic_policy import SNSTopicDangerousPolicyActionsRule
from tests.utils import get_cfmodel_from


@fixture()
def sqs_policy():
    return get_cfmodel_from("rules/SNSTopicDangerousPolicyActionsRule/bad_template.yaml").resolve()


def test_sns_dangerous_policy_actions(sqs_policy):
    rule = SNSTopicDangerousPolicyActionsRule(None)
    result = rule.invoke(sqs_policy)

    assert not result.valid
    assert len(result.failed_rules) == 1
    assert len(result.failed_monitored_rules) == 0
    assert result.failed_rules[0].risk_value == RuleRisk.MEDIUM
    assert result.failed_rules[0].rule == "SNSTopicDangerousPolicyActionsRule"
    assert (
        result.failed_rules[0].reason == "SNS Topic policy mysnspolicyA should not not include the following dangerous "
        "actions: ['sns:AddPermission', 'sns:RemovePermission', 'sns:TagResource', 'sns:UntagResource']"
    )
