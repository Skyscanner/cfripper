import pytest

from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rules import SNSTopicPolicyNotPrincipalRule
from tests.utils import compare_lists_of_failures, get_cfmodel_from


@pytest.fixture()
def sns_topic_not_principal():
    return get_cfmodel_from("rules/SNSTopicPolicyNotPrincipalRule/bad_template.json").resolve()


def test_sns_topic_not_principal(sns_topic_not_principal):
    rule = SNSTopicPolicyNotPrincipalRule(None)
    result = rule.invoke(sns_topic_not_principal)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="SNS Topic policy mysnspolicyA should not allow Allow and NotPrincipal at the same time",
                risk_value=RuleRisk.MEDIUM,
                rule="SNSTopicPolicyNotPrincipalRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"mysnspolicyA"},
                resource_types={"AWS::SNS::TopicPolicy"},
            )
        ],
    )


def test_rule_supports_filter_config(sns_topic_not_principal, default_allow_all_config):
    rule = SNSTopicPolicyNotPrincipalRule(default_allow_all_config)
    result = rule.invoke(sns_topic_not_principal)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])
