"""
Copyright 2018-2020 Skyscanner Ltd

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
"""
__all__ = ["SecurityGroupOpenToWorldRule", "SecurityGroupIngressOpenToWorldRule", "SecurityGroupMissingEgressRule"]

from typing import Dict, Optional

from pycfmodel.model.cf_model import CFModel
from pycfmodel.model.resources.properties.security_group_ingress_prop import SecurityGroupIngressProp
from pycfmodel.model.resources.security_group import SecurityGroup
from pycfmodel.model.resources.security_group_ingress import SecurityGroupIngress

from cfripper.model.enums import RuleGranularity, RuleMode
from cfripper.model.result import Result
from cfripper.rules.base_rules import Rule


class SecurityGroupOpenToWorldRule(Rule):
    """
    Checks if security groups have an ingress rule of /0 for ports other than 80 and 443.
    All other ports should be closed off from public access to prevent a serious security misconfiguration.

    Fix:
        Most security groups only need to be access privately, and this can typically be done by specifying
        the CIDR of a Security Group's ingress to `10.0.0.0/8` or similar (https://en.wikipedia.org/wiki/Private_network).

    Code for fix:
        ````json
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "SecurityGroup": {
                    "Type": "AWS::EC2::SecurityGroup",
                    "Properties": {
                        "GroupDescription": "description",
                        "SecurityGroupIngress": [
                            // this is compliant. Port 22 (typically SSH) is accessible from the private network only.
                            {
                                "IpProtocol": "tcp",
                                "CidrIp": "10.0.0.0/8",
                                "FromPort": 22,
                                "ToPort": 22
                            },
                            // this is not compliant. Anyone with the IP for this EC2 instance can connect on port 9090.
                            {
                                "IpProtocol": "tcp",
                                "CidrIp": "0.0.0.0/0",
                                "FromPort": 9090,
                                "ToPort": 9090
                            }
                        ]
                    }
                }
            }
        }
        ````
    """

    GRANULARITY = RuleGranularity.RESOURCE
    REASON = "Port {} open to the world in security group '{}'"

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, SecurityGroup) and resource.Properties.SecurityGroupIngress:
                list_security_group_ingress = resource.Properties.SecurityGroupIngress
                if not isinstance(list_security_group_ingress, list):
                    list_security_group_ingress = [list_security_group_ingress]
                for ingress in list_security_group_ingress:
                    if self.non_compliant_ip_range(item=ingress):
                        for port in range(ingress.FromPort, ingress.ToPort + 1):
                            if str(port) not in self._config.allowed_world_open_ports:
                                self.add_failure_to_result(
                                    result, self.REASON.format(port, logical_id), resource_ids={logical_id}
                                )
        return result

    def non_compliant_ip_range(self, item) -> bool:
        cidr_ip = item.CidrIp if isinstance(item, SecurityGroupIngressProp) else item.Properties.CidrIp
        cidr_ipv6 = item.CidrIpv6 if isinstance(item, SecurityGroupIngressProp) else item.Properties.CidrIpv6

        return (
            item.ipv4_slash_zero()
            or item.ipv6_slash_zero()
            or (cidr_ip and cidr_ip.is_global)
            or (cidr_ipv6 and cidr_ipv6.is_global)
        )


class SecurityGroupIngressOpenToWorldRule(SecurityGroupOpenToWorldRule):
    """
    Checks if a security group has a CIDR open to world on ingress.
    This is a security risk as your resource may be publicly available.

    Fix:
        Unless required, do not use the following IP ranges in your Security Group Ingress:
          - 0.0.0.0/0.
          - Any `/8` that does not start with 10.
          - 172/8 or 192/8 (use 172.16/12 and 192.168/16 ranges, per RFC1918 specification).

        As per RFC4193, fd00::/8 IPv6 addresses should be used to define a private network.
    """

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, SecurityGroupIngress) and self.non_compliant_ip_range(item=resource):
                for port in range(resource.Properties.FromPort, resource.Properties.ToPort + 1):
                    if str(port) not in self._config.allowed_world_open_ports:
                        self.add_failure_to_result(
                            result, self.REASON.format(port, logical_id), resource_ids={logical_id}
                        )
        return result


class SecurityGroupMissingEgressRule(Rule):
    """
    Checks that Security Groups are defined with an egress policy, even if this is still allowing all
    outbound traffic.

    Risk:
        If no egress rule is specified, the default is to open all outbound traffic to the world. Whilst
        some services may need this, it is usually the case that the security group can be locked down
        more. A NAT instance for example may require a completely open egress policy.

        Allowing unrestricted (0.0.0.0/0 or ::/0) outbound/egress access can increase opportunities for
        malicious activity such as such as Denial of Service (DoS) attacks or Distributed Denial of Service (DDoS)
        attacks.

    Fix:
        Explicitly defining the egress policy for the security group.

    Code for fix:
        Even in the example below, the egress rule added will allow HTTP traffic out to the world. However,
        this will pass the rule.

        ````json
        // example from https://stelligent.com/2016/04/07/finding-security-problems-early-in-the-development-process-of-a-cloudformation-template-with-cfn-nag/
        {
            "Resources": {
                "sg": {
                    "Type": "AWS::EC2::SecurityGroup",
                    "Properties": {
                        "GroupDescription": "some_group_desc",
                        "SecurityGroupIngress": {
                            "CidrIp": "10.1.2.3/32",
                            "FromPort": 34,
                            "ToPort": 34,
                            "IpProtocol": "tcp"
                        },
                        // addition of egress to the `sg` resource
                        "SecurityGroupEgress": {
                            "CidrIp": "0.0.0.0/0",
                            "FromPort": 80,
                            "ToPort": 80,
                            "IpProtocol": "tcp"
                        },
                        "VpcId": "vpc-12345678"
                    }
                }
            }
        }
        ````
    """

    GRANULARITY = RuleGranularity.RESOURCE
    REASON = (
        "Missing egress rule in {} means all traffic is allowed outbound. Make this explicit if it is desired "
        "configuration"
    )
    RULE_MODE = RuleMode.DEBUG

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, SecurityGroup) and not resource.Properties.SecurityGroupEgress:
                self.add_failure_to_result(result, self.REASON.format(logical_id), resource_ids={logical_id})
        return result
