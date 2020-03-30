from pytest import fixture

from cfripper.config.config import Config
from cfripper.rules import SecurityGroupIngressOpenToWorldRule
from tests.utils import get_cfmodel_from


@fixture()
def bad_template():
    return get_cfmodel_from("rules/SecurityGroupIngressOpenToWorld/bad_template.json").resolve()


@fixture()
def good_template():
    return get_cfmodel_from("rules/SecurityGroupIngressOpenToWorld/good_template.json").resolve()


def test_failures_are_raised(bad_template):
    rule = SecurityGroupIngressOpenToWorldRule(Config())
    result = rule.invoke(bad_template)

    assert not result.valid
    assert len(result.failed_rules) == 2
    assert len(result.failed_monitored_rules) == 0
    assert result.failed_rules[0].rule == "SecurityGroupIngressOpenToWorldRule"
    assert result.failed_rules[0].reason == "Port 46 open to the world in security group 'securityGroupIngress1'"
    assert result.failed_rules[1].rule == "SecurityGroupIngressOpenToWorldRule"
    assert result.failed_rules[1].reason == "Port 46 open to the world in security group 'securityGroupIngress2'"


def test_valid_security_group_ingress(good_template):
    rule = SecurityGroupIngressOpenToWorldRule(Config())
    result = rule.invoke(good_template)
    assert result.valid
