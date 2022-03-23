import pytest
from pycfmodel.model.cf_model import CFModel

from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rules.iam_roles import IAMRolesOverprivilegedRule
from tests.utils import compare_lists_of_failures, get_cfmodel_from


@pytest.fixture()
def valid_role_inline_policy() -> CFModel:
    return get_cfmodel_from("rules/IAMRolesOverprivilegedRule/valid_role_inline_policy.json").resolve()


@pytest.fixture()
def invalid_role_inline_policy() -> CFModel:
    return get_cfmodel_from("rules/IAMRolesOverprivilegedRule/invalid_role_inline_policy.json").resolve()


@pytest.fixture()
def invalid_role_inline_policy_resource_as_array() -> CFModel:
    return get_cfmodel_from(
        "rules/IAMRolesOverprivilegedRule/invalid_role_inline_policy_resource_as_array.json"
    ).resolve()


@pytest.fixture()
def valid_role_managed_policy() -> CFModel:
    return get_cfmodel_from("rules/IAMRolesOverprivilegedRule/valid_role_managed_policy.json").resolve()


@pytest.fixture()
def invalid_role_managed_policy() -> CFModel:
    return get_cfmodel_from("rules/IAMRolesOverprivilegedRule/invalid_role_managed_policy.json").resolve()


@pytest.fixture()
def invalid_role_inline_policy_fn_if() -> CFModel:
    return get_cfmodel_from("rules/IAMRolesOverprivilegedRule/invalid_role_inline_policy_fn_if.json").resolve()


def test_with_valid_role_inline_policy(valid_role_inline_policy):
    rule = IAMRolesOverprivilegedRule(None)
    result = rule.invoke(valid_role_inline_policy)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_with_invalid_role_inline_policy(invalid_role_inline_policy):
    rule = IAMRolesOverprivilegedRule(None)
    result = rule.invoke(invalid_role_inline_policy)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="Role 'RootRole' contains an insecure permission 'ec2:DeleteInternetGateway' in policy 'not_so_chill_policy'",
                risk_value=RuleRisk.MEDIUM,
                rule="IAMRolesOverprivilegedRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"RootRole"},
                resource_types={"AWS::IAM::Role"},
            )
        ],
    )


def test_with_invalid_role_inline_policy_resource_as_array(invalid_role_inline_policy_resource_as_array):
    rule = IAMRolesOverprivilegedRule(None)
    result = rule.invoke(invalid_role_inline_policy_resource_as_array)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="Role 'RootRole' contains an insecure permission 'ec2:DeleteInternetGateway' in policy 'not_so_chill_policy'",
                risk_value=RuleRisk.MEDIUM,
                rule="IAMRolesOverprivilegedRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"RootRole"},
                resource_types={"AWS::IAM::Role"},
            )
        ],
    )


def test_with_valid_role_managed_policy(valid_role_managed_policy):
    rule = IAMRolesOverprivilegedRule(None)
    result = rule.invoke(valid_role_managed_policy)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_with_invalid_role_managed_policy(invalid_role_managed_policy):
    rule = IAMRolesOverprivilegedRule(None)
    result = rule.invoke(invalid_role_managed_policy)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="Role RootRole has forbidden Managed Policy arn:aws:iam::aws:policy/AdministratorAccess",
                risk_value=RuleRisk.MEDIUM,
                rule="IAMRolesOverprivilegedRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"RootRole"},
                resource_types={"AWS::IAM::Role"},
            )
        ],
    )


def test_with_invalid_role_inline_policy_fn_if(invalid_role_inline_policy_fn_if):
    rule = IAMRolesOverprivilegedRule(None)
    result = rule.invoke(invalid_role_inline_policy_fn_if)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="Role 'RootRole' contains an insecure permission 'ec2:DeleteVpc' in policy 'ProdCredentialStoreAccessPolicy'",
                risk_value=RuleRisk.MEDIUM,
                rule="IAMRolesOverprivilegedRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"RootRole"},
                resource_types={"AWS::IAM::Role"},
            )
        ],
    )


def test_rule_supports_filter_config(invalid_role_managed_policy, default_allow_all_config):
    rule = IAMRolesOverprivilegedRule(default_allow_all_config)
    result = rule.invoke(invalid_role_managed_policy)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])
