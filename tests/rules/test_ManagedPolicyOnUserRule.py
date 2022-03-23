from pytest import fixture

from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rules import ManagedPolicyOnUserRule
from tests.utils import compare_lists_of_failures, get_cfmodel_from


@fixture()
def good_template():
    return get_cfmodel_from("rules/ManagedPolicyOnUserRule/good_template.json").resolve()


@fixture()
def bad_template():
    return get_cfmodel_from("rules/ManagedPolicyOnUserRule/bad_template.json").resolve()


def test_no_failures_are_raised(good_template):
    rule = ManagedPolicyOnUserRule(None)
    result = rule.invoke(good_template)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_failures_are_raised(bad_template):
    rule = ManagedPolicyOnUserRule(None)
    result = rule.invoke(bad_template)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="IAM managed policy DirectManagedPolicy should not apply directly to users. Should be on group",
                risk_value=RuleRisk.MEDIUM,
                rule="ManagedPolicyOnUserRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"DirectManagedPolicy"},
                resource_types={"AWS::IAM::ManagedPolicy"},
            )
        ],
    )


def test_rule_supports_filter_config(bad_template, default_allow_all_config):
    rule = ManagedPolicyOnUserRule(default_allow_all_config)
    result = rule.invoke(bad_template)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])
