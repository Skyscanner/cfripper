import pytest

from cfripper.config.config import Config
from cfripper.config.filter import Filter
from cfripper.config.rule_config import RuleConfig
from cfripper.model.enums import RuleMode
from cfripper.rule_processor import RuleProcessor
from cfripper.rules import DEFAULT_RULES
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

    assert not result.valid
    assert len(result.failed_rules) == 1
    assert len(result.failed_monitored_rules) == 0
    assert result.failed_rules[0].rule == "EC2SecurityGroupMissingEgressRule"
    assert (
        result.failed_rules[0].reason
        == "Missing egress rule in sg means all traffic is allowed outbound. Make this explicit if it is desired configuration"
    )


def test_security_group_with_egress(security_group_with_egress):
    rule = EC2SecurityGroupMissingEgressRule(None)
    result = rule.invoke(security_group_with_egress)

    assert result.valid
    assert len(result.failed_rules) == 0
    assert len(result.failed_monitored_rules) == 0


def test_filter_do_not_report_anything(single_security_group_one_cidr_ingress):
    mock_config = Config(
        rules=["EC2SecurityGroupMissingEgressRule"],
        aws_account_id="123456789",
        stack_name="mockstack",
        rules_config={
            "EC2SecurityGroupMissingEgressRule": RuleConfig(
                filters=[
                    Filter(rule_mode=RuleMode.WHITELISTED, eval={"eq": [{"ref": "config.stack_name"}, "mockstack"]},)
                ],
            )
        },
    )
    rules = [DEFAULT_RULES.get(rule)(mock_config) for rule in mock_config.rules]
    processor = RuleProcessor(*rules)
    result = processor.process_cf_template(single_security_group_one_cidr_ingress, mock_config)

    assert result.valid


def test_non_matching_filters_are_reported_normally(single_security_group_one_cidr_ingress):
    mock_config = Config(
        rules=["EC2SecurityGroupMissingEgressRule"],
        aws_account_id="123456789",
        stack_name="mockstack",
        rules_config={
            "EC2SecurityGroupMissingEgressRule": RuleConfig(
                filters=[
                    Filter(rule_mode=RuleMode.WHITELISTED, eval={"eq": [{"ref": "config.stack_name"}, "anotherstack"]})
                ],
            )
        },
    )
    rules = [DEFAULT_RULES.get(rule)(mock_config) for rule in mock_config.rules]
    processor = RuleProcessor(*rules)
    result = processor.process_cf_template(single_security_group_one_cidr_ingress, mock_config)

    assert not result.valid
    assert len(result.failed_rules) == 1
    assert len(result.failed_monitored_rules) == 0
    assert result.failed_rules[0].rule == "EC2SecurityGroupMissingEgressRule"
    assert (
        result.failed_rules[0].reason
        == "Missing egress rule in sg means all traffic is allowed outbound. Make this explicit if it is desired configuration"
    )
