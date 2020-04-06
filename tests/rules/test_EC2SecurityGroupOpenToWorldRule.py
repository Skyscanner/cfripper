import pytest

from cfripper.config.config import Config
from cfripper.config.filter import Filter
from cfripper.config.rule_config import RuleConfig
from cfripper.model.enums import RuleMode
from cfripper.rule_processor import RuleProcessor
from cfripper.rules import DEFAULT_RULES, EC2SecurityGroupOpenToWorldRule
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


def test_filter_do_not_report_anything(invalid_security_group_range):
    mock_config = Config(
        rules=["EC2SecurityGroupOpenToWorldRule"],
        aws_account_id="123456789",
        stack_name="mockstack",
        rules_config={
            "EC2SecurityGroupOpenToWorldRule": RuleConfig(
                filters=[
                    Filter(
                        rule_mode=RuleMode.WHITELISTED,
                        eval={
                            "and": [
                                {"eq": [{"ref": "config.stack_name"}, "mockstack"]},
                                {"eq": [{"ref": "open_ports"}, list(range(0, 101))]},
                            ]
                        },
                    )
                ],
            )
        },
    )
    rules = [DEFAULT_RULES.get(rule)(mock_config) for rule in mock_config.rules]
    processor = RuleProcessor(*rules)
    result = processor.process_cf_template(invalid_security_group_range, mock_config)

    assert result.valid


def test_non_matching_filters_are_reported_normally(invalid_security_group_range):
    mock_config = Config(
        rules=["EC2SecurityGroupOpenToWorldRule"],
        aws_account_id="123456789",
        stack_name="mockstack",
        rules_config={
            "EC2SecurityGroupOpenToWorldRule": RuleConfig(
                filters=[
                    Filter(rule_mode=RuleMode.WHITELISTED, eval={"eq": [{"ref": "config.stack_name"}, "anotherstack"]})
                ],
            )
        },
    )
    rules = [DEFAULT_RULES.get(rule)(mock_config) for rule in mock_config.rules]
    processor = RuleProcessor(*rules)
    result = processor.process_cf_template(invalid_security_group_range, mock_config)

    assert not result.valid
    assert result.failed_rules[0].rule == "EC2SecurityGroupOpenToWorldRule"
    assert (
        result.failed_rules[0].reason
        == "Port(s) 0-79, 81-100 open to public IPs: (11.0.0.0/8) in security group 'SecurityGroup'"
    )
