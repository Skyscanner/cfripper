import pytest

from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rules.cloudformation_authentication import CloudFormationAuthenticationRule
from tests.utils import compare_lists_of_failures, get_cfmodel_from


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
    assert compare_lists_of_failures(result.failures, [])


def test_failures_are_raised(bad_template):
    rule = CloudFormationAuthenticationRule(None)
    result = rule.invoke(bad_template)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="Hardcoded credentials in EC2I4LBA1",
                risk_value=RuleRisk.MEDIUM,
                rule="CloudFormationAuthenticationRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"EC2I4LBA1"},
                resource_types={"AWS::EC2::Instance"},
            )
        ],
    )


def test_rule_ignores_where_auth_not_mentioned(neutral_template):
    rule = CloudFormationAuthenticationRule(None)
    result = rule.invoke(neutral_template)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_rule_supports_filter_config(bad_template, default_allow_all_config):
    rule = CloudFormationAuthenticationRule(default_allow_all_config)
    result = rule.invoke(bad_template)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])
