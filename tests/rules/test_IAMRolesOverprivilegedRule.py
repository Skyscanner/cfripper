import pytest
from pycfmodel.model.cf_model import CFModel

from cfripper.rules.iam_roles import IAMRolesOverprivilegedRule
from tests.utils import get_cfmodel_from


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
    assert len(result.failed_rules) == 0
    assert len(result.failed_monitored_rules) == 0


def test_with_invalid_role_inline_policy(invalid_role_inline_policy):
    rule = IAMRolesOverprivilegedRule(None)
    result = rule.invoke(invalid_role_inline_policy)

    assert not result.valid
    assert len(result.failed_rules) == 1
    assert len(result.failed_monitored_rules) == 0
    assert result.failed_rules[0].rule == "IAMRolesOverprivilegedRule"
    assert (
        result.failed_rules[0].reason
        == "Role 'RootRole' contains an insecure permission 'ec2:DeleteInternetGateway' in policy 'not_so_chill_policy'"
    )


def test_with_invalid_role_inline_policy_resource_as_array(invalid_role_inline_policy_resource_as_array):
    rule = IAMRolesOverprivilegedRule(None)
    result = rule.invoke(invalid_role_inline_policy_resource_as_array)

    assert not result.valid
    assert len(result.failed_rules) == 1
    assert len(result.failed_monitored_rules) == 0
    assert result.failed_rules[0].rule == "IAMRolesOverprivilegedRule"
    assert (
        result.failed_rules[0].reason
        == "Role 'RootRole' contains an insecure permission 'ec2:DeleteInternetGateway' in policy 'not_so_chill_policy'"
    )


def test_with_valid_role_managed_policy(valid_role_managed_policy):
    rule = IAMRolesOverprivilegedRule(None)
    result = rule.invoke(valid_role_managed_policy)

    assert result.valid
    assert len(result.failed_rules) == 0
    assert len(result.failed_monitored_rules) == 0


def test_with_invalid_role_managed_policy(invalid_role_managed_policy):
    rule = IAMRolesOverprivilegedRule(None)
    result = rule.invoke(invalid_role_managed_policy)

    assert not result.valid
    assert len(result.failed_rules) == 1
    assert len(result.failed_monitored_rules) == 0
    assert result.failed_rules[0].rule == "IAMRolesOverprivilegedRule"
    assert (
        result.failed_rules[0].reason
        == "Role RootRole has forbidden Managed Policy arn:aws:iam::aws:policy/AdministratorAccess"
    )


def test_with_invalid_role_inline_policy_fn_if(invalid_role_inline_policy_fn_if):
    rule = IAMRolesOverprivilegedRule(None)
    result = rule.invoke(invalid_role_inline_policy_fn_if)

    assert not result.valid
    assert len(result.failed_rules) == 1
    assert len(result.failed_monitored_rules) == 0
    assert result.failed_rules[0].rule == "IAMRolesOverprivilegedRule"
    assert (
        result.failed_rules[0].reason
        == "Role 'RootRole' contains an insecure permission 'ec2:DeleteVpc' in policy 'ProdCredentialStoreAccessPolicy'"
    )
