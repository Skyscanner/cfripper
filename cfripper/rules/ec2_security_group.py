__all__ = [
    "EC2SecurityGroupIngressOpenToWorldRule",
    "EC2SecurityGroupMissingEgressRule",
    "EC2SecurityGroupOpenToWorldRule",
]

from abc import ABC
from itertools import groupby
from operator import itemgetter
from typing import Dict, List, Optional, Tuple, Union

from pycfmodel.model.cf_model import CFModel
from pycfmodel.model.resources.properties.security_group_ingress_prop import SecurityGroupIngressProp
from pycfmodel.model.resources.security_group import SecurityGroup
from pycfmodel.model.resources.security_group_ingress import SecurityGroupIngress, SecurityGroupIngressProperties

from cfripper.model.enums import RuleGranularity
from cfripper.model.result import Result
from cfripper.rules.base_rules import Rule


class SecurityGroupOpenToWorldRule(Rule, ABC):
    """
    Base class not intended to be instantiated, but inherited from.
    This class provides common methods used to detect open ports.
    """

    GRANULARITY = RuleGranularity.RESOURCE
    REASON = "Port(s) {} open to public IPs: ({}) in security group '{}'"

    def analyse_ingress(
        self,
        result: Result,
        logical_id: str,
        ingress: Union[SecurityGroupIngressProp, SecurityGroupIngressProperties],
        filters_available_context: Dict,
    ):
        if self.non_compliant_ip_range(ingress=ingress):
            open_ports = list(range(ingress.FromPort, ingress.ToPort + 1))
            non_allowed_open_ports = sorted(set(open_ports) - set(self._config.allowed_world_open_ports))

            if non_allowed_open_ports:
                ip_range = ingress.CidrIp or ingress.CidrIpv6
                filters_available_context["ingress_obj"] = ingress
                filters_available_context["ingress_ip"] = str(ip_range)
                filters_available_context["open_ports"] = open_ports
                filters_available_context["non_allowed_open_ports"] = non_allowed_open_ports

                self.add_failure_to_result(
                    result,
                    self.REASON.format(self.get_open_ports_wording(non_allowed_open_ports), ip_range, logical_id,),
                    resource_ids={logical_id},
                    context=filters_available_context,
                )

    def get_open_ports_wording(self, non_allowed_open_ports: List[int]) -> str:
        formatted_ports_range = []
        for port_range_start, port_range_end in self.get_open_ports_ranges(non_allowed_open_ports):
            if port_range_start == port_range_end:
                formatted_ports_range.append(f"{port_range_start}")
            else:
                formatted_ports_range.append(f"{port_range_start}-{port_range_end}")
        return ", ".join(formatted_ports_range)

    def get_open_ports_ranges(self, open_ports: List[int]) -> List[Tuple[int, int]]:
        open_ports_ranges = []
        for k, group in groupby(enumerate(open_ports), lambda x: x[1] - x[0]):
            port_range = list(map(itemgetter(1), group))
            open_ports_ranges.append((port_range[0], port_range[-1]))
        return open_ports_ranges

    def non_compliant_ip_range(
        self, ingress: Optional[Union[SecurityGroupIngressProp, SecurityGroupIngressProperties]]
    ) -> bool:
        if ingress is None:
            return False
        return (
            ingress.ipv4_slash_zero()
            or ingress.ipv6_slash_zero()
            or (ingress.CidrIp and ingress.CidrIp.is_global)
            or (ingress.CidrIpv6 and ingress.CidrIpv6.is_global)
        )


class EC2SecurityGroupOpenToWorldRule(SecurityGroupOpenToWorldRule):
    """
    Checks if security groups have an ingress IP that is open to the world for ports other than 80 and 443.
    All other ports should be closed off from public access to prevent a serious security misconfiguration.

    Fix:
        Most security groups only need to be [accessed privately](https://en.wikipedia.org/wiki/Private_network), and
        this can typically be done by specifying the CIDR of a Security Group's ingress to `10.0.0.0/8` or similar.

        Unless required, do not use the following IP ranges in your Security Group Ingress:

          - `0.0.0.0/0`.

          - Any `/8` that does not start with 10.

          - `172/8` or `192/8` (use `172.16/12` and `192.168/16` ranges, per RFC1918 specification).

        As per RFC4193, `fd00::/8` IPv6 addresses should be used to define a private network.

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

    Filters context:
        | Parameter               | Type                       | Description                                                    |
        |:-----------------------:|:--------------------------:|:--------------------------------------------------------------:|
        |`config`                 | str                        | `config` variable available inside the rule                    |
        |`extras`                 | str                        | `extras` variable available inside the rule                    |
        |`logical_id`             | str                        | ID used in Cloudformation to refer the resource being analysed |
        |`resource`               | `SecurityGroup`            | Resource that is being addressed                               |
        |`ingress_ip`             | str                        | IP Address range (IpV4 or IpV6) of the ingress object          |
        |`ingress_obj`            | `SecurityGroupIngressProp` | SecurityGroupIngressProp being checked found in the Resource   |
        |`open_ports`             | `List[int]`                | List of all open ports defined                                 |
        |`non_allowed_open_ports` | `List[int]`                | List of all non allowed open ports defined                     |
    """

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()
        for logical_id, resource in cfmodel.resources_filtered_by_type({SecurityGroup}).items():
            list_security_group_ingress = resource.Properties.SecurityGroupIngress
            if not isinstance(list_security_group_ingress, list):
                list_security_group_ingress = [list_security_group_ingress]
            for ingress in list_security_group_ingress:
                filters_available_context = {
                    "config": self._config,
                    "extras": extras,
                    "logical_id": logical_id,
                    "resource": resource,
                }
                self.analyse_ingress(result, logical_id, ingress, filters_available_context)
        return result


class EC2SecurityGroupIngressOpenToWorldRule(SecurityGroupOpenToWorldRule):
    """
    Checks if security groups have an ingress IP that is open to the world for ports other than 80 and 443.
    All other ports should be closed off from public access to prevent a serious security misconfiguration.

    Fix:
        Most security groups only need to be [accessed privately](https://en.wikipedia.org/wiki/Private_network), and
        this can typically be done by specifying the CIDR of a Security Group's ingress to `10.0.0.0/8` or similar.

        Unless required, do not use the following IP ranges in your Security Group Ingress:

          - `0.0.0.0/0`.

          - Any `/8` that does not start with 10.

          - `172/8` or `192/8` (use `172.16/12` and `192.168/16` ranges, per RFC1918 specification).

        As per RFC4193, `fd00::/8` IPv6 addresses should be used to define a private network.

    Code for fix:
        ````json
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                // this is compliant. Port 22 (typically SSH) is accessible from the private network only.
                "InboundRule1": {
                    "Type": "AWS::EC2::SecurityGroupIngress",
                    "Properties": {
                        "GroupId": {
                            "Fn::GetAtt": [
                                "TargetSG",
                                "GroupId"
                            ]
                        },
                        "CidrIp": "10.0.0.0/8",
                        "IpProtocol": "tcp",
                        "FromPort": "22",
                        "ToPort": "22",
                        "SourceSecurityGroupId": "sg-12345678",
                        "SourceSecurityGroupOwnerId": "123456789012"
                    }
                },
                // this is not compliant. Anyone with the IP for this EC2 instance can connect on port 9090.
                "InboundRule2": {
                    "Type": "AWS::EC2::SecurityGroupIngress",
                    "Properties": {
                        "GroupId": {
                            "Fn::GetAtt": [
                                "TargetSG",
                                "GroupId"
                            ]
                        },
                        "CidrIp": "0.0.0.0/0",
                        "IpProtocol": "tcp",
                        "FromPort": "9090",
                        "ToPort": "9090",
                        "SourceSecurityGroupId": "sg-12345678",
                        "SourceSecurityGroupOwnerId": "123456789012"
                    }
                }
            }
        }
        ````

    Filters context:
        | Parameter               | Type                             | Description                                                    |
        |:-----------------------:|:--------------------------------:|:--------------------------------------------------------------:|
        |`config`                 | str                              | `config` variable available inside the rule                    |
        |`extras`                 | str                              | `extras` variable available inside the rule                    |
        |`logical_id`             | str                              | ID used in Cloudformation to refer the resource being analysed |
        |`resource`               | `SecurityGroupIngress`           | Resource that is being addressed                               |
        |`ingress_ip`             | str                              | IP Address range (IpV4 or IpV6) of the ingress object          |
        |`ingress_obj`            | `SecurityGroupIngressProperties` | SecurityGroupIngress being checked found in the Resource       |
        |`open_ports`             | `List[int]`                      | List of all open ports defined                                 |
        |`non_allowed_open_ports` | `List[int]`                      | List of all non allowed open ports defined                     |
    """

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()
        for logical_id, resource in cfmodel.resources_filtered_by_type({SecurityGroupIngress}).items():
            filters_available_context = {
                "config": self._config,
                "extras": extras,
                "logical_id": logical_id,
                "resource": resource,
            }
            self.analyse_ingress(result, logical_id, resource.Properties, filters_available_context)
        return result


class EC2SecurityGroupMissingEgressRule(Rule):
    """
    Checks that Security Groups are defined with an egress policy, even if this is still allowing all
    outbound traffic.

    Risk:
        If no egress rule is specified, the default is to open all outbound traffic to the world. Whilst
        some services may need this, it is usually the case that the security group can be locked down
        more. A NAT instance for example may require a completely open egress policy.

        Allowing unrestricted (`0.0.0.0/0` or `::/0`) outbound/egress access can increase opportunities for
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

    Filters context:
        | Parameter   | Type            | Description                                                    |
        |:-----------:|:---------------:|:--------------------------------------------------------------:|
        |`config`     | str             | `config` variable available inside the rule                    |
        |`extras`     | str             | `extras` variable available inside the rule                    |
        |`logical_id` | str             | ID used in Cloudformation to refer the resource being analysed |
        |`resource`   | `SecurityGroup` | Resource that is being addressed                               |
    """

    GRANULARITY = RuleGranularity.RESOURCE
    REASON = (
        "Missing egress rule in {} means all traffic is allowed outbound. Make this explicit if it is desired "
        "configuration"
    )

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, SecurityGroup) and not resource.Properties.SecurityGroupEgress:
                self.add_failure_to_result(
                    result,
                    self.REASON.format(logical_id),
                    resource_ids={logical_id},
                    context={"config": self._config, "extras": extras, "logical_id": logical_id, "resource": resource},
                )
        return result
