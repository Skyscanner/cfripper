import pytest

from cfripper.rules.ec2_security_group import EC2SecurityGroupMissingEgressRule
from tests.utils import get_cfmodel_from


@pytest.fixture()
def single_security_group_one_cidr_ingress():
    return get_cfmodel_from(
        "rules/EC2SecurityGroupMissingEgressRule/single_security_group_one_cidr_ingress.json"
    ).resolve()


@pytest.fixture()
def security_group_with_egress():
    return get_cfmodel_from("rules/EC2SecurityGroupMissingEgressRule/security_group_with_egress.json").resolve()


def test_single_security_group_one_cidr_ingress(single_security_group_one_cidr_ingress):
    rule = EC2SecurityGroupMissingEgressRule(None)
    result = rule.invoke(single_security_group_one_cidr_ingress)

    assert result.valid
    assert len(result.failed_rules) == 0
    assert len(result.failed_monitored_rules) == 1
    assert result.failed_monitored_rules[0].rule == "EC2SecurityGroupMissingEgressRule"
    assert (
        result.failed_monitored_rules[0].reason
        == "Missing egress rule in sg means all traffic is allowed outbound. Make this explicit if it is desired configuration"
    )


def test_security_group_with_egress(security_group_with_egress):
    rule = EC2SecurityGroupMissingEgressRule(None)
    result = rule.invoke(security_group_with_egress)

    assert result.valid
    assert len(result.failed_rules) == 0
    assert len(result.failed_monitored_rules) == 0
