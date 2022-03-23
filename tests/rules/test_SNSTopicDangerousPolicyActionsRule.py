from pytest import fixture

from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rules.sns_topic_policy import SNSTopicDangerousPolicyActionsRule
from tests.utils import compare_lists_of_failures, get_cfmodel_from


@fixture()
def sqs_policy():
    return get_cfmodel_from("rules/SNSTopicDangerousPolicyActionsRule/bad_template.yaml").resolve()


def test_sns_dangerous_policy_actions(sqs_policy):
    rule = SNSTopicDangerousPolicyActionsRule(None)
    result = rule.invoke(sqs_policy)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.ACTION,
                reason="SNS Topic policy mysnspolicyA should not not include the following dangerous actions: ['sns:AddPermission', 'sns:RemovePermission', 'sns:TagResource', 'sns:UntagResource']",
                risk_value=RuleRisk.MEDIUM,
                rule="SNSTopicDangerousPolicyActionsRule",
                rule_mode=RuleMode.BLOCKING,
                actions={"sns:RemovePermission", "sns:UntagResource", "sns:AddPermission", "sns:TagResource"},
                resource_ids={"mysnspolicyA"},
                resource_types={"AWS::SNS::TopicPolicy"},
            )
        ],
    )


def test_rule_supports_filter_config(sqs_policy, default_allow_all_config):
    rule = SNSTopicDangerousPolicyActionsRule(default_allow_all_config)
    result = rule.invoke(sqs_policy)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])
