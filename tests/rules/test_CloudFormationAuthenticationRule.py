import pytest

from cfripper.rules.cloudformation_authentication import CloudFormationAuthenticationRule
from tests.utils import get_cfmodel_from


@pytest.fixture()
def good_template():
    return get_cfmodel_from("rules/CloudFormationAuthenticationRule/cfn_authentication_good.json").resolve()


@pytest.fixture()
def neutral_template():
    return get_cfmodel_from("rules/CloudFormationAuthenticationRule/cfn_authentication_neutral.yml").resolve()


@pytest.fixture()
def bad_template():
    return get_cfmodel_from("rules/CloudFormationAuthenticationRule/cfn_authentication_bad.json").resolve()


def test_no_failures_are_raised(good_template):
    rule = CloudFormationAuthenticationRule(None)
    result = rule.invoke(good_template)

    assert result.valid
    assert len(result.failed_rules) == 0
    assert len(result.failed_monitored_rules) == 0


def test_failures_are_raised(bad_template):
    rule = CloudFormationAuthenticationRule(None)
    result = rule.invoke(bad_template)

    assert not result.valid
    assert len(result.failed_rules) == 1
    assert len(result.failed_monitored_rules) == 0
    assert result.failed_rules[0].rule == "CloudFormationAuthenticationRule"
    assert result.failed_rules[0].reason == "Hardcoded credentials in EC2I4LBA1"


def test_rule_ignores_where_auth_not_mentioned(neutral_template):
    rule = CloudFormationAuthenticationRule(None)
    result = rule.invoke(neutral_template)

    assert result.valid
    assert len(result.failed_rules) == 0
    assert len(result.failed_monitored_rules) == 0
