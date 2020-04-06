from pytest import fixture

from cfripper.config.config import Config
from cfripper.config.filter import Filter
from cfripper.config.rule_config import RuleConfig
from cfripper.model.enums import RuleMode
from cfripper.rule_processor import RuleProcessor
from cfripper.rules import DEFAULT_RULES, EC2SecurityGroupIngressOpenToWorldRule
from tests.utils import get_cfmodel_from


@fixture()
def bad_template():
    return get_cfmodel_from("rules/EC2SecurityGroupIngressOpenToWorld/bad_template.json").resolve()


@fixture()
def good_template():
    return get_cfmodel_from("rules/EC2SecurityGroupIngressOpenToWorld/good_template.json").resolve()


def test_failures_are_raised(bad_template):
    rule = EC2SecurityGroupIngressOpenToWorldRule(Config())
    result = rule.invoke(bad_template)

    assert not result.valid
    assert len(result.failed_rules) == 2
    assert len(result.failed_monitored_rules) == 0
    assert result.failed_rules[0].rule == "EC2SecurityGroupIngressOpenToWorldRule"
    assert (
        result.failed_rules[0].reason
        == "Port(s) 46 open to public IPs: (11.0.0.0/8) in security group 'securityGroupIngress1'"
    )
    assert result.failed_rules[1].rule == "EC2SecurityGroupIngressOpenToWorldRule"
    assert (
        result.failed_rules[1].reason
        == "Port(s) 46 open to public IPs: (::/0) in security group 'securityGroupIngress2'"
    )


def test_valid_security_group_ingress(good_template):
    rule = EC2SecurityGroupIngressOpenToWorldRule(Config())
    result = rule.invoke(good_template)
    assert result.valid


def test_filter_do_not_report_anything(bad_template):
    mock_config = Config(
        rules=["EC2SecurityGroupIngressOpenToWorldRule"],
        aws_account_id="123456789",
        stack_name="mockstack",
        rules_config={
            "EC2SecurityGroupIngressOpenToWorldRule": RuleConfig(
                filters=[
                    Filter(
                        rule_mode=RuleMode.WHITELISTED,
                        eval={
                            "and": [
                                {"eq": [{"ref": "config.stack_name"}, "mockstack"]},
                                {"eq": [{"ref": "ingress.FromPort"}, 46]},
                            ]
                        },
                    )
                ],
            )
        },
    )
    rules = [DEFAULT_RULES.get(rule)(mock_config) for rule in mock_config.rules]
    processor = RuleProcessor(*rules)
    result = processor.process_cf_template(bad_template, mock_config)

    assert result.valid


def test_non_matching_filters_are_reported_normally(bad_template):
    mock_config = Config(
        rules=["EC2SecurityGroupIngressOpenToWorldRule"],
        aws_account_id="123456789",
        stack_name="mockstack",
        rules_config={
            "EC2SecurityGroupIngressOpenToWorldRule": RuleConfig(
                filters=[
                    Filter(rule_mode=RuleMode.WHITELISTED, eval={"eq": [{"ref": "config.stack_name"}, "anotherstack"]})
                ],
            )
        },
    )
    rules = [DEFAULT_RULES.get(rule)(mock_config) for rule in mock_config.rules]
    processor = RuleProcessor(*rules)
    result = processor.process_cf_template(bad_template, mock_config)
    assert not result.valid
    assert len(result.failed_rules) == 2
    assert len(result.failed_monitored_rules) == 0
    assert result.failed_rules[0].rule == "EC2SecurityGroupIngressOpenToWorldRule"
    assert (
        result.failed_rules[0].reason
        == "Port(s) 46 open to public IPs: (11.0.0.0/8) in security group 'securityGroupIngress1'"
    )
    assert result.failed_rules[1].rule == "EC2SecurityGroupIngressOpenToWorldRule"
    assert (
        result.failed_rules[1].reason
        == "Port(s) 46 open to public IPs: (::/0) in security group 'securityGroupIngress2'"
    )
