__all__ = ["EBSVolumeHasSSERule"]

from typing import Dict, Optional

from pycfmodel.model.cf_model import CFModel

from cfripper.model.enums import RuleGranularity
from cfripper.model.result import Result
from cfripper.rules.base_rules import Rule


class EBSVolumeHasSSERule(Rule):
    """
    Checks that server side encryption is enabled for all EBS volumes.

    Risk:
        Data that is not encrypted at rest could breach regulatory compliance
        and allow easier access for an attacker to view any instace storage data
        of your EC2 instance.

    Fix:
        Enable server-side encryption on EBS volumes.

    Code for fix:
        ````json
        {
            "Type" : "AWS::EC2::Volume",
            "Properties" : {
                ...
                "Encrypted" : true,
                ...
            }
        }
        ````
    """

    REASON = "EBS volume {} should have server-side encryption enabled"
    GRANULARITY = RuleGranularity.RESOURCE

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()
        for logical_id, resource in cfmodel.Resources.items():
            if resource.Type == "AWS::EC2::Volume":
                if resource.Properties.get("Encrypted") != "true":
                    self.add_failure_to_result(result, self.REASON.format(logical_id), resource_ids={logical_id})
        return result
