from pytest import fixture

from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rules.privilege_escalation import PrivilegeEscalationRule
from tests.utils import compare_lists_of_failures, get_cfmodel_from


@fixture()
def valid_role_inline_policy():
    return get_cfmodel_from("rules/PrivilegeEscalationRule/valid_role_inline_policy.json").resolve()


@fixture()
def privilege_escalation_role_cf():
    return get_cfmodel_from("rules/PrivilegeEscalationRule/privilege_escalation_role.yaml").resolve()


@fixture()
def valid_privilege_escalation_on_s3_bucket_policy():
    return get_cfmodel_from("rules/PrivilegeEscalationRule/privilege_escalation_s3_bucket_policy.yaml").resolve()


def test_valid_role_inline_policy(valid_role_inline_policy):
    rule = PrivilegeEscalationRule(None)
    result = rule.invoke(valid_role_inline_policy)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.ACTION,
                reason="PolicyA has blacklisted IAM actions: ['iam:AddUserToGroup', 'iam:CreatePolicy']",
                risk_value=RuleRisk.HIGH,
                rule="PrivilegeEscalationRule",
                rule_mode=RuleMode.BLOCKING,
                actions={"iam:AddUserToGroup", "iam:CreatePolicy"},
                resource_ids={"PolicyA"},
                resource_types={"AWS::IAM::Policy"},
            )
        ],
    )


def test_privilege_escalation_using_role(privilege_escalation_role_cf):
    rule = PrivilegeEscalationRule(None)
    result = rule.invoke(privilege_escalation_role_cf)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.ACTION,
                reason="PrivilegeInjectorRole has blacklisted IAM actions: ['iam:UpdateAssumeRolePolicy']",
                risk_value=RuleRisk.HIGH,
                rule="PrivilegeEscalationRule",
                rule_mode=RuleMode.BLOCKING,
                actions={"iam:UpdateAssumeRolePolicy"},
                resource_ids={"PrivilegeInjectorRole"},
                resource_types={"AWS::IAM::Role"},
            )
        ],
    )


def test_valid_privilege_escalation_on_s3_bucket_policy(valid_privilege_escalation_on_s3_bucket_policy):
    rule = PrivilegeEscalationRule(None)
    result = rule.invoke(valid_privilege_escalation_on_s3_bucket_policy)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_rule_supports_filter_config(privilege_escalation_role_cf, default_allow_all_config):
    rule = PrivilegeEscalationRule(default_allow_all_config)
    result = rule.invoke(privilege_escalation_role_cf)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])
