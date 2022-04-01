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

    Filters context:
        | Parameter               | Type                             | Description                                                    |
        |:-----------------------:|:--------------------------------:|:--------------------------------------------------------------:|
        |`config`                 | str                              | `config` variable available inside the rule                    |
        |`extras`                 | str                              | `extras` variable available inside the rule                    |
        |`logical_id`             | str                              | ID used in Cloudformation to refer the resource being analysed |
        |`resource`               | `Resource`                       | EC2 Volume that is being addressed                             |
    """

    REASON = "EBS volume {} should have server-side encryption enabled"
    GRANULARITY = RuleGranularity.RESOURCE

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()
        for logical_id, resource in cfmodel.resources_filtered_by_type("AWS::EC2::Volume").items():
            encrypted_status = getattr(resource.Properties, "Encrypted", None)

            if encrypted_status is None or encrypted_status is False:
                self.add_failure_to_result(
                    result,
                    self.REASON.format(logical_id),
                    resource_ids={logical_id},
                    resource_types={resource.Type},
                    context={"config": self._config, "extras": extras, "logical_id": logical_id, "resource": resource},
                )
        return result
