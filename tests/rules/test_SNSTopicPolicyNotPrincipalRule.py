import pytest

from cfripper.rules import SNSTopicPolicyNotPrincipalRule
from tests.utils import get_cfmodel_from


@pytest.fixture()
def sns_topic_not_principal():
    return get_cfmodel_from("rules/SNSTopicPolicyNotPrincipalRule/bad_template.json").resolve()


def test_sns_topic_not_principal(sns_topic_not_principal):
    rule = SNSTopicPolicyNotPrincipalRule(None)
    result = rule.invoke(sns_topic_not_principal)

    assert not result.valid
    assert len(result.failed_rules) == 1
    assert len(result.failed_monitored_rules) == 0
    assert result.failed_rules[0].rule == "SNSTopicPolicyNotPrincipalRule"
    assert (
        result.failed_rules[0].reason
        == "SNS Topic policy mysnspolicyA should not allow Allow and NotPrincipal at the same time"
    )
