import pytest

from cfripper.model.result import Failure
from cfripper.rules.public_elb_checker_rule import PublicELBCheckerRule
from tests.utils import get_cfmodel_from


@pytest.mark.parametrize(
    "template",
    [
        "rules/PublicELBCheckerRule/private_elb_instance.yml",
        "rules/PublicELBCheckerRule/private_elb_v2_instance.yml",
    ],
)
def test_invoke_private_elbs_passes(template):
    rule = PublicELBCheckerRule(None)
    rule._config.stack_name = "stackname"
    result = rule.invoke(cfmodel=get_cfmodel_from(template).resolve())

    assert result.valid
    assert result.failures == []


@pytest.mark.parametrize(
    "template, logical_id, resource_type, reason",
    [
        (
            "rules/PublicELBCheckerRule/public_facing_elb_instance.yml",
            "PublicLoadBalancer",
            "AWS::ElasticLoadBalancing::LoadBalancer",
            "Creation of public facing ELBs is restricted. LogicalId: PublicLoadBalancer",
        ),
        (
            "rules/PublicELBCheckerRule/public_facing_elb_v2_instance.yml",
            "PublicV2LoadBalancer",
            "AWS::ElasticLoadBalancingV2::LoadBalancer",
            "Creation of public facing ELBs is restricted. LogicalId: PublicV2LoadBalancer",
        ),
    ],
)
def test_invoke_public_elbs_fail(template, logical_id, resource_type, reason):
    rule = PublicELBCheckerRule(None)
    rule._config.stack_name = "stackname"
    result = rule.invoke(cfmodel=get_cfmodel_from(template).resolve())

    assert result.valid is False
    assert result.failures == [
        Failure(
            granularity="RESOURCE",
            reason=reason,
            risk_value="LOW",
            rule="PublicELBCheckerRule",
            rule_mode="BLOCKING",
            actions=None,
            resource_ids={logical_id},
            resource_types={resource_type},
        )
    ]
