import pytest

from cfripper.config.config import Config
from cfripper.config.filter import Filter
from cfripper.config.rule_configs.allow_http_ports_open_to_world import (
    allow_http_ports_open_to_world_rules_config_filter,
)
from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rule_processor import RuleProcessor
from cfripper.rules import DEFAULT_RULES, EC2SecurityGroupOpenToWorldRule
from tests.utils import compare_lists_of_failures, get_cfmodel_from


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


@pytest.fixture()
def invalid_security_group_port78_81():
    return get_cfmodel_from("rules/EC2SecurityGroupOpenToWorldRule/invalid_security_group_port78_81.json").resolve()


@pytest.fixture()
def invalid_security_group_no_ports_defined():
    return get_cfmodel_from(
        "rules/EC2SecurityGroupOpenToWorldRule/invalid_security_group_no_ports_defined.json"
    ).resolve()


def test_security_group_type_slash0(security_group_type_slash0):
    rule = EC2SecurityGroupOpenToWorldRule(None)
    result = rule.invoke(security_group_type_slash0)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="Port(s) 22 open to public IPs: (0.0.0.0/0) in security group 'SecurityGroup'",
                risk_value=RuleRisk.MEDIUM,
                rule="EC2SecurityGroupOpenToWorldRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"SecurityGroup"},
                resource_types={"AWS::EC2::SecurityGroup"},
            )
        ],
    )


def test_valid_security_group_not_slash0(valid_security_group_not_slash0):
    rule = EC2SecurityGroupOpenToWorldRule(None)
    result = rule.invoke(valid_security_group_not_slash0)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_valid_security_group_port80(valid_security_group_port80):
    rule = EC2SecurityGroupOpenToWorldRule(
        Config(
            rules=["EC2SecurityGroupOpenToWorldRule"],
            aws_account_id="123456789",
            stack_name="mockstack",
            rules_filters=[allow_http_ports_open_to_world_rules_config_filter],
        )
    )
    result = rule.invoke(valid_security_group_port80)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_valid_security_group_port443(valid_security_group_port443):
    rule = EC2SecurityGroupOpenToWorldRule(
        Config(
            rules=["EC2SecurityGroupOpenToWorldRule"],
            aws_account_id="123456789",
            stack_name="mockstack",
            rules_filters=[allow_http_ports_open_to_world_rules_config_filter],
        )
    )
    result = rule.invoke(valid_security_group_port443)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_invalid_security_group_port78_81(invalid_security_group_port78_81):
    rule = EC2SecurityGroupOpenToWorldRule(
        Config(
            rules=["EC2SecurityGroupOpenToWorldRule"],
            aws_account_id="123456789",
            stack_name="mockstack",
            rules_filters=[allow_http_ports_open_to_world_rules_config_filter],
        )
    )
    result = rule.invoke(invalid_security_group_port78_81)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="Port(s) 78-81 open to public IPs: (0.0.0.0/0) in security group 'SecurityGroup'",
                risk_value=RuleRisk.MEDIUM,
                rule="EC2SecurityGroupOpenToWorldRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"SecurityGroup"},
                resource_types={"AWS::EC2::SecurityGroup"},
            )
        ],
    )


def test_invalid_security_group_no_ports_defined(invalid_security_group_no_ports_defined):
    rule = EC2SecurityGroupOpenToWorldRule(
        Config(
            rules=["EC2SecurityGroupOpenToWorldRule"],
            aws_account_id="123456789",
            stack_name="mockstack",
        )
    )
    result = rule.invoke(invalid_security_group_no_ports_defined)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="Port(s) 0-65535 open to public IPs: (23.45.67.88/29) in security group 'SecurityGroup'",
                risk_value=RuleRisk.MEDIUM,
                rule="EC2SecurityGroupOpenToWorldRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"SecurityGroup"},
                resource_types={"AWS::EC2::SecurityGroup"},
            )
        ],
    )


def test_invalid_security_group_cidripv6(invalid_security_group_cidripv6):
    rule = EC2SecurityGroupOpenToWorldRule(None)
    result = rule.invoke(invalid_security_group_cidripv6)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="Port(s) 22 open to public IPs: (::/0) in security group 'SecurityGroup'",
                risk_value=RuleRisk.MEDIUM,
                rule="EC2SecurityGroupOpenToWorldRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"SecurityGroup"},
                resource_types={"AWS::EC2::SecurityGroup"},
            )
        ],
    )


def test_invalid_security_group_range(invalid_security_group_range):
    rule = EC2SecurityGroupOpenToWorldRule(None)
    result = rule.invoke(invalid_security_group_range)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="Port(s) 0-100 open to public IPs: (11.0.0.0/8) in security group 'SecurityGroup'",
                risk_value=RuleRisk.MEDIUM,
                rule="EC2SecurityGroupOpenToWorldRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"SecurityGroup"},
                resource_types={"AWS::EC2::SecurityGroup"},
            )
        ],
    )


def test_invalid_security_group_multiple_statements(invalid_security_group_multiple_statements):
    rule = EC2SecurityGroupOpenToWorldRule(None)
    result = rule.invoke(invalid_security_group_multiple_statements)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="Port(s) 9090 open to public IPs: (172.0.0.0/8) in security group 'SecurityGroup'",
                risk_value=RuleRisk.MEDIUM,
                rule="EC2SecurityGroupOpenToWorldRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"SecurityGroup"},
                resource_types={"AWS::EC2::SecurityGroup"},
            )
        ],
    )


def test_filter_do_not_report_anything(invalid_security_group_range):
    mock_config = Config(
        rules=["EC2SecurityGroupOpenToWorldRule"],
        aws_account_id="123456789",
        stack_name="mockstack",
        rules_filters=[
            Filter(
                rule_mode=RuleMode.ALLOWED,
                eval={
                    "and": [
                        {"eq": [{"ref": "config.stack_name"}, "mockstack"]},
                        {"eq": [{"ref": "open_ports"}, list(range(0, 101))]},
                    ]
                },
                rules={"EC2SecurityGroupOpenToWorldRule"},
            )
        ],
    )
    rules = [DEFAULT_RULES.get(rule)(mock_config) for rule in mock_config.rules]
    processor = RuleProcessor(*rules)
    result = processor.process_cf_template(invalid_security_group_range, mock_config)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_non_matching_filters_are_reported_normally(invalid_security_group_range):
    mock_config = Config(
        rules=["EC2SecurityGroupOpenToWorldRule"],
        aws_account_id="123456789",
        stack_name="mockstack",
        rules_filters=[
            Filter(
                rule_mode=RuleMode.ALLOWED,
                eval={"eq": [{"ref": "config.stack_name"}, "anotherstack"]},
                rules={"EC2SecurityGroupOpenToWorldRule"},
            )
        ],
    )
    rules = [DEFAULT_RULES.get(rule)(mock_config) for rule in mock_config.rules]
    processor = RuleProcessor(*rules)
    result = processor.process_cf_template(invalid_security_group_range, mock_config)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="Port(s) 0-100 open to public IPs: (11.0.0.0/8) in security group 'SecurityGroup'",
                risk_value=RuleRisk.MEDIUM,
                rule="EC2SecurityGroupOpenToWorldRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"SecurityGroup"},
                resource_types={"AWS::EC2::SecurityGroup"},
            )
        ],
    )
