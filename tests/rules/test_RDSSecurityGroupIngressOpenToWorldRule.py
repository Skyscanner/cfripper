from pytest import fixture

from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rules import RDSSecurityGroupIngressOpenToWorldRule
from tests.utils import compare_lists_of_failures, get_cfmodel_from


@fixture()
def rds_sg():
    return get_cfmodel_from("rules/RDSSecurityGroupIngressOpenToWorldRule/rds_sg.yaml").resolve()


@fixture()
def rds_sg_ingress():
    return get_cfmodel_from("rules/RDSSecurityGroupIngressOpenToWorldRule/rds_sg_ingress.yaml").resolve()


def test_dangerous_rds_securitygroup(rds_sg):
    rule = RDSSecurityGroupIngressOpenToWorldRule(None)
    result = rule.invoke(rds_sg)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                actions=None,
                granularity=RuleGranularity.RESOURCE,
                reason=(
                    "RDS DB Security group NonCompliantRDSSecurityGroup " + "should not have ingress open to the world"
                ),
                risk_value=RuleRisk.HIGH,
                rule="RDSSecurityGroupIngressOpenToWorldRule",
                rule_mode=RuleMode.BLOCKING,
                resource_ids={"NonCompliantRDSSecurityGroup"},
                resource_types={"AWS::RDS::DBSecurityGroup"},
            )
        ],
    )


def test_dangerous_rds_securitygroup_ingress(rds_sg_ingress):
    rule = RDSSecurityGroupIngressOpenToWorldRule(None)
    result = rule.invoke(rds_sg_ingress)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                actions=None,
                granularity=RuleGranularity.RESOURCE,
                reason=(
                    "RDS DB Security group NonCompliantRDSSecurityGroupIngress "
                    + "should not have ingress open to the world"
                ),
                risk_value=RuleRisk.HIGH,
                rule="RDSSecurityGroupIngressOpenToWorldRule",
                rule_mode=RuleMode.BLOCKING,
                resource_ids={"NonCompliantRDSSecurityGroupIngress"},
                resource_types={"AWS::RDS::DBSecurityGroupIngress"},
            )
        ],
    )


def test_rule_supports_filter_config(rds_sg, default_allow_all_config):
    rule = RDSSecurityGroupIngressOpenToWorldRule(default_allow_all_config)
    result = rule.invoke(rds_sg)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])
