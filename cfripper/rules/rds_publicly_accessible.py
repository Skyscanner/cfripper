__all__ = ["RDSInstancePubliclyAccessibleRule"]

from typing import Dict, Optional

from cfripper.model.enums import RuleGranularity, RuleRisk
from cfripper.model.result import Result
from cfripper.rules.base_rules import Rule


class RDSInstancePubliclyAccessibleRule(Rule):
    """
    Checks that RDS database instances and clusters are not publicly accessible.

    Risk:
        When `PubliclyAccessible` is set to `true`, the database endpoint resolves to a public IP address and can be
        reached from the internet if the attached security groups allow it. Exposing a database directly to the
        internet increases the attack surface (credential brute forcing, exploitation of engine vulnerabilities) and
        a single permissive security group rule is enough to expose the data.

    Fix:
        Set `PubliclyAccessible` to `false` (or remove it, as `false` is the default when a private DB subnet group
        is used) and reach the database through the VPC, a VPN, a bastion host or AWS Systems Manager Session Manager.

    Code for fix:
        ````yml
        Resources:
          Database:
            Type: AWS::RDS::DBInstance
            Properties:
              ...
              PubliclyAccessible: false
              ...
        ````

    Filters context:
        | Parameter     | Type       | Description                                                    |
        |:-------------:|:----------:|:--------------------------------------------------------------:|
        |`config`       | str        | `config` variable available inside the rule                    |
        |`extras`       | str        | `extras` variable available inside the rule                    |
        |`logical_id`   | str        | ID used in Cloudformation to refer the resource being analysed |
        |`resource`     | `Resource` | RDS resource that is being addressed                           |
    """

    REASON = "RDS resource {} should not be publicly accessible, set PubliclyAccessible to false"
    GRANULARITY = RuleGranularity.RESOURCE
    RISK_VALUE = RuleRisk.HIGH
    RESOURCE_TYPES = ("AWS::RDS::DBInstance", "AWS::RDS::DBCluster")

    def invoke(self, cfmodel, extras: Optional[Dict] = None) -> Result:
        result = Result()
        for resource_type in self.RESOURCE_TYPES:
            for logical_id, resource in cfmodel.resources_filtered_by_type(resource_type).items():
                publicly_accessible = getattr(resource.Properties, "PubliclyAccessible", None)
                if publicly_accessible is True or str(publicly_accessible).lower() == "true":
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
                        },
                    )
        return result
