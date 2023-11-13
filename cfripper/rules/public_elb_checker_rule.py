from typing import Dict, Optional

from pycfmodel.model.resources.generic_resource import GenericResource

from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Result
from cfripper.rules.base_rules import ResourceSpecificRule


class PublicELBCheckerRule(ResourceSpecificRule):
    """
    Rule to check if a public facing ELB is being created.
    """

    RESOURCE_TYPES = (GenericResource,)
    ELB_RESOURCE_TYPES = ["AWS::ElasticLoadBalancing::LoadBalancer", "AWS::ElasticLoadBalancingV2::LoadBalancer"]
    RISK_VALUE = RuleRisk.LOW
    RULE_MODE = RuleMode.BLOCKING
    REASON = "Creation of public facing ELBs is restricted. LogicalId: {}"

    def resource_invoke(self, resource: GenericResource, logical_id: str, extras: Optional[Dict] = None) -> Result:
        result = Result()
        if resource.Type in self.ELB_RESOURCE_TYPES:
            elb_scheme = getattr(resource.Properties, "Scheme", "internal")

            if elb_scheme == "internet-facing":
                self.add_failure_to_result(
                    result=result,
                    reason=self.REASON.format(logical_id),
                    resource_ids={logical_id},
                    resource_types={resource.Type},
                    context={
                        "config": self._config,
                        "extras": extras,
                        "logical_id": logical_id,
                        "resource": resource,
                    },
                    granularity=RuleGranularity.RESOURCE,
                )

        return result
