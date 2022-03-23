__all__ = ["KMSKeyEnabledKeyRotation"]

import logging
from typing import Dict, Optional

from pycfmodel.model.cf_model import CFModel

from cfripper.model.enums import RuleGranularity, RuleRisk
from cfripper.model.result import Result
from cfripper.rules.base_rules import Rule

logger = logging.getLogger(__file__)


class KMSKeyEnabledKeyRotation(Rule):
    """
    Check if EnableKeyRotation is true for symmetric KMS keys in principals in KMS Policies.

    Fix:
        Set EnableKeyRotation to true for any symmetric KMS key.

    Filters context:
        | Parameter           | Type                | Description                                                   |
        |:-------------------:|:------------------:|:--------------------------------------------------------------:|
        |`config`             | str                | `config` variable available inside the rule                    |
        |`extras`             | str                | `extras` variable available inside the rule                    |
        |`logical_id`         | str                | ID used in Cloudformation to refer the resource being analysed |
        |`resource`           | `KMSKey`           | Resource that is being addressed                               |
    """

    GRANULARITY = RuleGranularity.RESOURCE
    REASON = "KMS Key {} should have the key rotation enabled for symmetric keys"
    RISK_VALUE = RuleRisk.HIGH

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()
        for logical_id, resource in cfmodel.resources_filtered_by_type("AWS::KMS::Key").items():
            if not resource.Properties.KeySpec or resource.Properties.KeySpec == "SYMMETRIC_DEFAULT":
                if not resource.Properties.EnableKeyRotation or resource.Properties.EnableKeyRotation is False:
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
