"""
Copyright 2018-2019 Skyscanner Ltd

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
"""
import pytest

from cfripper.model.result import Result
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
    result = Result()
    rule = SecurityGroupOpenToWorldRule(None, result)
    rule.invoke(security_group_type_slash0)

    assert not result.valid
    assert result.failed_rules[0].rule == "SecurityGroupOpenToWorldRule"
    assert result.failed_rules[0].reason == "Port 22 open to the world in security group 'SecurityGroup'"


def test_valid_security_group_not_slash0(valid_security_group_not_slash0):
    result = Result()
    rule = SecurityGroupOpenToWorldRule(None, result)
    rule.invoke(valid_security_group_not_slash0)

    assert result.valid
    assert len(result.failed_rules) == 0
    assert len(result.failed_monitored_rules) == 0


def test_valid_security_group_port80(valid_security_group_port80):
    result = Result()
    rule = SecurityGroupOpenToWorldRule(None, result)
    rule.invoke(valid_security_group_port80)

    assert result.valid
    assert len(result.failed_rules) == 0
    assert len(result.failed_monitored_rules) == 0


def test_valid_security_group_port443(valid_security_group_port443):
    result = Result()
    rule = SecurityGroupOpenToWorldRule(None, result)
    rule.invoke(valid_security_group_port443)

    assert result.valid
    assert len(result.failed_rules) == 0
    assert len(result.failed_monitored_rules) == 0


def test_invalid_security_group_cidripv6(invalid_security_group_cidripv6):
    result = Result()
    rule = SecurityGroupOpenToWorldRule(None, result)
    rule.invoke(invalid_security_group_cidripv6)

    assert not result.valid
    assert result.failed_rules[0].rule == "SecurityGroupOpenToWorldRule"
    assert result.failed_rules[0].reason == "Port 22 open to the world in security group 'SecurityGroup'"


def test_invalid_security_group_range(invalid_security_group_range):
    result = Result()
    rule = SecurityGroupOpenToWorldRule(None, result)
    rule.invoke(invalid_security_group_range)

    assert not result.valid
    assert result.failed_rules[0].rule == "SecurityGroupOpenToWorldRule"
    assert result.failed_rules[0].reason == "Port 0 open to the world in security group 'SecurityGroup'"


def test_invalid_security_group_multiple_statements(invalid_security_group_multiple_statements):
    result = Result()
    rule = SecurityGroupOpenToWorldRule(None, result)
    rule.invoke(invalid_security_group_multiple_statements)

    assert not result.valid
    assert result.failed_rules[0].rule == "SecurityGroupOpenToWorldRule"
    assert result.failed_rules[0].reason == "Port 9090 open to the world in security group 'SecurityGroup'"
