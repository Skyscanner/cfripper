import pytest

from cfripper.rules import EC2SecurityGroupOpenToWorldRule
from tests.utils import get_cfmodel_from


@pytest.fixture()
def security_group_type_slash0():
    return get_cfmodel_from("rules/EC2SecurityGroupOpenToWorldRule/security_group_type_slash0.json").resolve()


@pytest.fixture()
def valid_security_group_not_slash0():
    return get_cfmodel_from("rules/EC2SecurityGroupOpenToWorldRule/valid_security_group_not_slash0.json").resolve()


@pytest.fixture()
def valid_security_group_port80():
    return get_cfmodel_from("rules/EC2SecurityGroupOpenToWorldRule/valid_security_group_port80.json").resolve()


@pytest.fixture()
def valid_security_group_port443():
    return get_cfmodel_from("rules/EC2SecurityGroupOpenToWorldRule/valid_security_group_port443.json").resolve()


@pytest.fixture()
def invalid_security_group_cidripv6():
    return get_cfmodel_from("rules/EC2SecurityGroupOpenToWorldRule/invalid_security_group_cidripv6.json").resolve()


@pytest.fixture()
def invalid_security_group_range():
    return get_cfmodel_from("rules/EC2SecurityGroupOpenToWorldRule/invalid_security_group_range.json").resolve()


@pytest.fixture()
def invalid_security_group_multiple_statements():
    return get_cfmodel_from(
        "rules/EC2SecurityGroupOpenToWorldRule/invalid_security_group_multiple_statements.json"
    ).resolve()


def test_security_group_type_slash0(security_group_type_slash0):
    rule = EC2SecurityGroupOpenToWorldRule(None)
    result = rule.invoke(security_group_type_slash0)

    assert not result.valid
    assert result.failed_rules[0].rule == "EC2SecurityGroupOpenToWorldRule"
    assert (
        result.failed_rules[0].reason == "Port(s) 22 open to public IPs: (0.0.0.0/0) in security group 'SecurityGroup'"
    )


def test_valid_security_group_not_slash0(valid_security_group_not_slash0):
    rule = EC2SecurityGroupOpenToWorldRule(None)
    result = rule.invoke(valid_security_group_not_slash0)

    assert result.valid
    assert len(result.failed_rules) == 0
    assert len(result.failed_monitored_rules) == 0


def test_valid_security_group_port80(valid_security_group_port80):
    rule = EC2SecurityGroupOpenToWorldRule(None)
    result = rule.invoke(valid_security_group_port80)

    assert result.valid
    assert len(result.failed_rules) == 0
    assert len(result.failed_monitored_rules) == 0


def test_valid_security_group_port443(valid_security_group_port443):
    rule = EC2SecurityGroupOpenToWorldRule(None)
    result = rule.invoke(valid_security_group_port443)

    assert result.valid
    assert len(result.failed_rules) == 0
    assert len(result.failed_monitored_rules) == 0


def test_invalid_security_group_cidripv6(invalid_security_group_cidripv6):
    rule = EC2SecurityGroupOpenToWorldRule(None)
    result = rule.invoke(invalid_security_group_cidripv6)

    assert not result.valid
    assert result.failed_rules[0].rule == "EC2SecurityGroupOpenToWorldRule"
    assert result.failed_rules[0].reason == "Port(s) 22 open to public IPs: (::/0) in security group 'SecurityGroup'"


def test_invalid_security_group_range(invalid_security_group_range):
    rule = EC2SecurityGroupOpenToWorldRule(None)
    result = rule.invoke(invalid_security_group_range)

    assert not result.valid
    assert result.failed_rules[0].rule == "EC2SecurityGroupOpenToWorldRule"
    assert (
        result.failed_rules[0].reason
        == "Port(s) 0-79, 81-100 open to public IPs: (11.0.0.0/8) in security group 'SecurityGroup'"
    )


def test_invalid_security_group_multiple_statements(invalid_security_group_multiple_statements):
    rule = EC2SecurityGroupOpenToWorldRule(None)
    result = rule.invoke(invalid_security_group_multiple_statements)

    assert not result.valid
    assert result.failed_rules[0].rule == "EC2SecurityGroupOpenToWorldRule"
    assert (
        result.failed_rules[0].reason
        == "Port(s) 9090 open to public IPs: (172.0.0.0/8) in security group 'SecurityGroup'"
    )
