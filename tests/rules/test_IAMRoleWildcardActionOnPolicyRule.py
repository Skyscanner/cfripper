import pytest

from cfripper.config.config import Config
from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rules.iam_roles import IAMRoleWildcardActionOnPolicyRule
from tests.utils import compare_lists_of_failures, get_cfmodel_from


@pytest.fixture()
def iam_role_with_wildcard_action():
    return get_cfmodel_from("rules/IAMRoleWildcardActionOnPolicyRule/iam_role_with_wildcard_action.json").resolve()


@pytest.fixture()
def iam_role_with_wildcard_action_on_trust():
    return get_cfmodel_from(
        "rules/IAMRoleWildcardActionOnPolicyRule/iam_role_with_wildcard_action_on_trust.json"
    ).resolve()


@pytest.fixture()
def iam_managed_policy_bad_template():
    return get_cfmodel_from(
        "rules/IAMRoleWildcardActionOnPolicyRule/iam_managed_policy_with_wildcard_action.json"
    ).resolve()


# following example from https://aws.amazon.com/premiumsupport/knowledge-center/explicit-deny-principal-elements-s3/
@pytest.fixture()
def iam_managed_policy_good_template_with_allow_and_deny():
    return get_cfmodel_from("rules/IAMRoleWildcardActionOnPolicyRule/iam_role_valid.json").resolve()


def test_valid_iam_policy_permissions(iam_role_with_wildcard_action):
    rule = IAMRoleWildcardActionOnPolicyRule(None)
    result = rule.invoke(iam_role_with_wildcard_action)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="IAM role WildcardActionRole should not allow a `*` action on its root policy",
                risk_value=RuleRisk.MEDIUM,
                rule="IAMRoleWildcardActionOnPolicyRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"WildcardActionRole"},
                resource_types={"AWS::IAM::Role"},
            )
        ],
    )


def test_valid_iam_policy_trust(iam_role_with_wildcard_action_on_trust):
    rule = IAMRoleWildcardActionOnPolicyRule(None)
    result = rule.invoke(iam_role_with_wildcard_action_on_trust)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="IAM role WildcardActionRole should not allow a `*` action on its AssumeRolePolicy",
                risk_value=RuleRisk.MEDIUM,
                rule="IAMRoleWildcardActionOnPolicyRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"WildcardActionRole"},
                resource_types={"AWS::IAM::Role"},
            )
        ],
    )


def test_invalid_managed_policy_template(iam_managed_policy_bad_template):
    rule = IAMRoleWildcardActionOnPolicyRule(Config(aws_account_id="123456789"))
    result = rule.invoke(iam_managed_policy_bad_template)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="IAM role CreateTestDBPolicy3 should not allow a `*` action on its AWS::IAM::ManagedPolicy",
                risk_value=RuleRisk.MEDIUM,
                rule="IAMRoleWildcardActionOnPolicyRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"CreateTestDBPolicy3"},
                resource_types={"AWS::IAM::ManagedPolicy"},
            )
        ],
    )


def test_valid_iam_role_no_errors(iam_managed_policy_good_template_with_allow_and_deny):
    rule = IAMRoleWildcardActionOnPolicyRule(None)
    result = rule.invoke(iam_managed_policy_good_template_with_allow_and_deny)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_rule_supports_filter_config(iam_managed_policy_bad_template, default_allow_all_config):
    rule = IAMRoleWildcardActionOnPolicyRule(default_allow_all_config)
    result = rule.invoke(iam_managed_policy_bad_template)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])
