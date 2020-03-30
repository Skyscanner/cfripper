import pytest

from cfripper.rules import SecurityGroupOpenToWorldRule
from tests.utils import get_cfmodel_from


@pytest.fixture()
def security_group_type_slash0():
    return get_cfmodel_from("rules/SecurityGroupOpenToWorldRule/security_group_type_slash0.json").resolve()


@pytest.fixture()
def valid_security_group_not_slash0():
    return get_cfmodel_from("rules/SecurityGroupOpenToWorldRule/valid_security_group_not_slash0.json").resolve()


@pytest.fixture()
def valid_security_group_port80():
    return get_cfmodel_from("rules/SecurityGroupOpenToWorldRule/valid_security_group_port80.json").resolve()


@pytest.fixture()
def valid_security_group_port443():
    return get_cfmodel_from("rules/SecurityGroupOpenToWorldRule/valid_security_group_port443.json").resolve()


@pytest.fixture()
def invalid_security_group_cidripv6():
    return get_cfmodel_from("rules/SecurityGroupOpenToWorldRule/invalid_security_group_cidripv6.json").resolve()


@pytest.fixture()
def invalid_security_group_range():
    return get_cfmodel_from("rules/SecurityGroupOpenToWorldRule/invalid_security_group_range.json").resolve()


@pytest.fixture()
def invalid_security_group_multiple_statements():
    return get_cfmodel_from(
        "rules/SecurityGroupOpenToWorldRule/invalid_security_group_multiple_statements.json"
    ).resolve()


def test_security_group_type_slash0(security_group_type_slash0):
    rule = SecurityGroupOpenToWorldRule(None)
    result = rule.invoke(security_group_type_slash0)

    assert not result.valid
    assert result.failed_rules[0].rule == "SecurityGroupOpenToWorldRule"
    assert result.failed_rules[0].reason == "Port 22 open to the world in security group 'SecurityGroup'"


def test_valid_security_group_not_slash0(valid_security_group_not_slash0):
    rule = SecurityGroupOpenToWorldRule(None)
    result = rule.invoke(valid_security_group_not_slash0)

    assert result.valid
    assert len(result.failed_rules) == 0
    assert len(result.failed_monitored_rules) == 0


def test_valid_security_group_port80(valid_security_group_port80):
    rule = SecurityGroupOpenToWorldRule(None)
    result = rule.invoke(valid_security_group_port80)

    assert result.valid
    assert len(result.failed_rules) == 0
    assert len(result.failed_monitored_rules) == 0


def test_valid_security_group_port443(valid_security_group_port443):
    rule = SecurityGroupOpenToWorldRule(None)
    result = rule.invoke(valid_security_group_port443)

    assert result.valid
    assert len(result.failed_rules) == 0
    assert len(result.failed_monitored_rules) == 0


def test_invalid_security_group_cidripv6(invalid_security_group_cidripv6):
    rule = SecurityGroupOpenToWorldRule(None)
    result = rule.invoke(invalid_security_group_cidripv6)

    assert not result.valid
    assert result.failed_rules[0].rule == "SecurityGroupOpenToWorldRule"
    assert result.failed_rules[0].reason == "Port 22 open to the world in security group 'SecurityGroup'"


def test_invalid_security_group_range(invalid_security_group_range):
    rule = SecurityGroupOpenToWorldRule(None)
    result = rule.invoke(invalid_security_group_range)

    assert not result.valid
    assert result.failed_rules[0].rule == "SecurityGroupOpenToWorldRule"
    assert result.failed_rules[0].reason == "Port 0 open to the world in security group 'SecurityGroup'"


def test_invalid_security_group_multiple_statements(invalid_security_group_multiple_statements):
    rule = SecurityGroupOpenToWorldRule(None)
    result = rule.invoke(invalid_security_group_multiple_statements)

    assert not result.valid
    assert result.failed_rules[0].rule == "SecurityGroupOpenToWorldRule"
    assert result.failed_rules[0].reason == "Port 9090 open to the world in security group 'SecurityGroup'"
