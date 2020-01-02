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
__all__ = ["SecurityGroupOpenToWorldRule", "SecurityGroupIngressOpenToWorld", "SecurityGroupMissingEgressRule"]

from pycfmodel.model.resources.security_group import SecurityGroup
from pycfmodel.model.resources.security_group_ingress import SecurityGroupIngress

from cfripper.model.enums import RuleGranularity, RuleMode
from cfripper.model.rule import Rule


class SecurityGroupOpenToWorldRule(Rule):
    """
    Rule that checks for open security groups
    """

    GRANULARITY = RuleGranularity.RESOURCE
    REASON = "Port {} open to the world in security group '{}'"

    def invoke(self, cfmodel):
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, SecurityGroup) and resource.Properties.SecurityGroupIngress:
                list_security_group_ingress = resource.Properties.SecurityGroupIngress
                if not isinstance(list_security_group_ingress, list):
                    list_security_group_ingress = [list_security_group_ingress]
                for ingress in list_security_group_ingress:
                    if ingress.ipv4_slash_zero() or ingress.ipv6_slash_zero():
                        for port in range(ingress.FromPort, ingress.ToPort + 1):
                            if str(port) not in self._config.allowed_world_open_ports:
                                self.add_failure(
                                    type(self).__name__, self.REASON.format(port, logical_id), resource_ids={logical_id}
                                )


class SecurityGroupIngressOpenToWorld(SecurityGroupOpenToWorldRule):
    """
    Rule that checks for open security groups ingress
    """

    def invoke(self, cfmodel):
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, SecurityGroupIngress) and (
                resource.ipv4_slash_zero() or resource.ipv6_slash_zero()
            ):
                for port in range(resource.Properties.FromPort, resource.Properties.ToPort + 1):
                    if str(port) not in self._config.allowed_world_open_ports:
                        self.add_failure(
                            type(self).__name__, self.REASON.format(port, logical_id), resource_ids={logical_id}
                        )


class SecurityGroupMissingEgressRule(Rule):
    """
    Rule that checks for open security groups egress
    """

    GRANULARITY = RuleGranularity.RESOURCE
    REASON = (
        "Missing egress rule in {} means all traffic is allowed outbound. Make this explicit if it is desired "
        "configuration"
    )
    RULE_MODE = RuleMode.MONITOR

    def invoke(self, cfmodel):
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, SecurityGroup) and not resource.Properties.SecurityGroupEgress:
                self.add_failure(type(self).__name__, self.REASON.format(logical_id), resource_ids={logical_id})
