from typing import Optional, Union

from pycfmodel.model.resources.security_group import RDSDBSecurityGroup
from pycfmodel.model.resources.security_group_ingress import RDSDBSecurityGroupIngress

from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Result
from cfripper.rules import ResourceSpecificRule


class RDSSecurityGroupIngressOpenToWorldRule(ResourceSpecificRule):
    """
    Checks if RDS native security groups have an ingress IP that is open to the world.

    Fix:
        Most security groups only need to be [accessed privately](https://en.wikipedia.org/wiki/Private_network), and
        this can typically be done by specifying the CIDR of a Security Group's ingress to `10.0.0.0/8` or similar.

        Unless required, do not use the following IP ranges in your Security Group Ingress:

          - `0.0.0.0/0`.

          - Any `/8` that does not start with 10.

          - `172/8` or `192/8` (use `172.16/12` and `192.168/16` ranges, per RFC1918 specification).

        As per RFC4193, `fd00::/8` IPv6 addresses should be used to define a private network.

    Code example:

        ```yaml
        Resources:
          CompliantRDSSecurityGroup:
            Type: AWS::RDS::DBSecurityGroup
            Properties:
              EC2VpcId: "vpc-id"
              DBSecurityGroupIngress:
                - CIDRIP: 10.0.0.0/8
              GroupDescription: Compliant RDS security group
          NonCompliantRDSSecurityGroup:
            Type: AWS::RDS::DBSecurityGroup
            Properties:
              EC2VpcId: "vpc-id"
              DBSecurityGroupIngress:
                - CIDRIP: 0.0.0.0/0
              GroupDescription: Risky RDS security group
        ```

    Filters context:
        | Parameter               | Type                                           | Description                                                    |
        |:-----------------------:|:----------------------------------------------:|:--------------------------------------------------------------:|
        |`config`                 | str                                            | `config` variable available inside the rule                    |
        |`extras`                 | str                                            | `extras` variable available inside the rule                    |
        |`logical_id`             | str                                            | ID used in Cloudformation to refer the resource being analysed |
        |`resource`               | `RDSDBSecurityGroup/RDSDBSecurityGroupIngress` | Resource that is being addressed                               |
        |`ingress_obj`            | `DBSecurityGroupIngressProp`                   | DBSecurityGroupIngress being checked found in the Resource     |
    """

    GRANULARITY = RuleGranularity.RESOURCE
    RESOURCE_TYPES = (RDSDBSecurityGroup, RDSDBSecurityGroupIngress)
    RULE_MODE = RuleMode.BLOCKING
    RISK_VALUE = RuleRisk.HIGH
    REASON = "RDS DB Security group {} should not have ingress open to the world"

    def resource_invoke(
        self,
        resource: Union[RDSDBSecurityGroup, RDSDBSecurityGroupIngress],
        logical_id: str,
        extras: Optional[dict] = None,
    ) -> Result:
        result = Result()

        if isinstance(resource, RDSDBSecurityGroupIngress):
            ingress_collection = [resource.Properties]
        else:  # isinstance(resource, RDSDBSecurityGroup)
            ingress_collection = resource.Properties.DBSecurityGroupIngress

        for ingress_entry in ingress_collection:
            if ingress_entry.is_public():
                self.add_failure_to_result(
                    result,
                    self.REASON.format(logical_id),
                    resource_ids={logical_id},
                    resource_types={resource.Type},
                    context={
                        "config": self._config,
                        "extras": extras,
                        "logical_id": logical_id,
                        "resource": resource,
                        "cirdip": ingress_entry.CIDRIP,
                    },
                )
        return result
