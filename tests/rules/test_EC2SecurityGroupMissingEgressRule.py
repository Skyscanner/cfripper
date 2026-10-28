import pytest

from cfripper.config.config import Config
from cfripper.config.filter import Filter
from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rule_processor import RuleProcessor
from cfripper.rules import DEFAULT_RULES
from cfripper.rules.ec2_security_group import EC2SecurityGroupMissingEgressRule
from tests.utils import compare_lists_of_failures, get_cfmodel_from


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
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="Missing egress rule in sg means all traffic is allowed outbound. Make this explicit if it is desired configuration",
                risk_value=RuleRisk.MEDIUM,
                rule="EC2SecurityGroupMissingEgressRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"sg"},
                resource_types={"AWS::EC2::SecurityGroup"},
            )
        ],
    )


def test_security_group_with_egress(security_group_with_egress):
    rule = EC2SecurityGroupMissingEgressRule(None)
    result = rule.invoke(security_group_with_egress)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def _missing_egress_failure(logical_id: str) -> Failure:
    return Failure(
        granularity=RuleGranularity.RESOURCE,
        reason=(
            f"Missing egress rule in {logical_id} means all traffic is allowed outbound. Make this explicit if it is "
            "desired configuration"
        ),
        risk_value=RuleRisk.MEDIUM,
        rule="EC2SecurityGroupMissingEgressRule",
        rule_mode=RuleMode.BLOCKING,
        actions=None,
        resource_ids={logical_id},
        resource_types={"AWS::EC2::SecurityGroup"},
    )


def test_standalone_egress_getatt_is_not_a_false_positive():
    rule = EC2SecurityGroupMissingEgressRule(None)
    # Leave Fn::GetAtt unresolved. resolve() replaces every GetAtt with the placeholder "GETATT".
    cfmodel = get_cfmodel_from(
        "rules/EC2SecurityGroupMissingEgressRule/security_group_with_standalone_egress_getatt.json"
    )
    result = rule.invoke(cfmodel)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_standalone_egress_dotted_getatt_is_not_a_false_positive():
    rule = EC2SecurityGroupMissingEgressRule(None)
    cfmodel = get_cfmodel_from(
        "rules/EC2SecurityGroupMissingEgressRule/security_group_with_standalone_egress_getatt_dotted.json"
    )
    result = rule.invoke(cfmodel)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_resolved_getatt_does_not_count_as_egress():
    rule = EC2SecurityGroupMissingEgressRule(None)
    cfmodel = get_cfmodel_from(
        "rules/EC2SecurityGroupMissingEgressRule/security_group_with_standalone_egress_getatt.json"
    ).resolve()
    result = rule.invoke(cfmodel)

    assert not result.valid
    assert compare_lists_of_failures(result.failures, [_missing_egress_failure("EC2SG")])


@pytest.mark.parametrize("resolve", [False, True])
def test_standalone_egress_ref_is_not_a_false_positive(resolve):
    rule = EC2SecurityGroupMissingEgressRule(None)
    cfmodel = get_cfmodel_from("rules/EC2SecurityGroupMissingEgressRule/security_group_with_standalone_egress_ref.json")
    if resolve:
        cfmodel = cfmodel.resolve()
    result = rule.invoke(cfmodel)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_only_the_security_group_without_standalone_egress_fails():
    rule = EC2SecurityGroupMissingEgressRule(None)
    cfmodel = get_cfmodel_from("rules/EC2SecurityGroupMissingEgressRule/two_security_groups_one_standalone_egress.json")
    result = rule.invoke(cfmodel)

    assert not result.valid
    assert compare_lists_of_failures(result.failures, [_missing_egress_failure("OtherSG")])


def test_physical_group_id_does_not_clear_missing_egress():
    rule = EC2SecurityGroupMissingEgressRule(None)
    cfmodel = get_cfmodel_from(
        "rules/EC2SecurityGroupMissingEgressRule/security_group_with_unrelated_physical_egress.json"
    ).resolve()
    result = rule.invoke(cfmodel)

    assert not result.valid
    assert compare_lists_of_failures(result.failures, [_missing_egress_failure("sg")])


def test_filter_do_not_report_anything(single_security_group_one_cidr_ingress):
    mock_config = Config(
        rules=["EC2SecurityGroupMissingEgressRule"],
        aws_account_id="123456789",
        stack_name="mockstack",
        rules_filters=[
            Filter(
                rule_mode=RuleMode.ALLOWED,
                eval={"eq": [{"ref": "config.stack_name"}, "mockstack"]},
                rules={"EC2SecurityGroupMissingEgressRule"},
            )
        ],
    )
    rules = [DEFAULT_RULES.get(rule)(mock_config) for rule in mock_config.rules]
    processor = RuleProcessor(*rules)
    result = processor.process_cf_template(single_security_group_one_cidr_ingress, mock_config)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_non_matching_filters_are_reported_normally(single_security_group_one_cidr_ingress):
    mock_config = Config(
        rules=["EC2SecurityGroupMissingEgressRule"],
        aws_account_id="123456789",
        stack_name="mockstack",
        rules_filters=[
            Filter(
                rule_mode=RuleMode.ALLOWED,
                eval={"eq": [{"ref": "config.stack_name"}, "anotherstack"]},
                rules={"EC2SecurityGroupMissingEgressRule"},
            )
        ],
    )
    rules = [DEFAULT_RULES.get(rule)(mock_config) for rule in mock_config.rules]
    processor = RuleProcessor(*rules)
    result = processor.process_cf_template(single_security_group_one_cidr_ingress, mock_config)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="Missing egress rule in sg means all traffic is allowed outbound. Make this explicit if it is desired configuration",
                risk_value=RuleRisk.MEDIUM,
                rule="EC2SecurityGroupMissingEgressRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"sg"},
                resource_types={"AWS::EC2::SecurityGroup"},
            )
        ],
    )
