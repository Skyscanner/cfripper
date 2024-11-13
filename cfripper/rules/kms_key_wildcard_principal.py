__all__ = ["KMSKeyWildcardPrincipalRule"]
import logging
import re
from typing import Dict, Optional

from pycfmodel.model.cf_model import CFModel
from pycfmodel.model.resources.kms_key import KMSKey

from cfripper.model.enums import RuleGranularity
from cfripper.model.result import Result
from cfripper.rules.base_rules import Rule

logger = logging.getLogger(__file__)


class KMSKeyWildcardPrincipalRule(Rule):
    """
    Check for wildcards in principals in KMS Policies.

    Filters context:
        | Parameter           | Type                               | Description                                                    |
        |:-------------------:|:----------------------------------:|:--------------------------------------------------------------:|
        |`config`             | str                                | `config` variable available inside the rule                    |
        |`extras`             | str                                | `extras` variable available inside the rule                    |
        |`logical_id`         | str                                | ID used in Cloudformation to refer the resource being analysed |
        |`resource`           | `KMSKey`                           | Resource that is being addressed                               |
        |`statement`          | `Statement`                        | Statement being checked found in the Resource                  |
        |`principal`          | str                                | AWS Principal being checked found in the statement             |
    """

    GRANULARITY = RuleGranularity.RESOURCE

    REASON = "KMS Key policy {} should not allow wildcard principals"
    CONTAINS_WILDCARD_PATTERN = re.compile(r"^(\w*:)?\*$")

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, KMSKey):
                if resource.Properties.KeyPolicy:
                    for statement in resource.Properties.KeyPolicy._statement_as_list():
                        filtered_principals = statement.principals_with(self.CONTAINS_WILDCARD_PATTERN)
                        if statement.Effect == "Allow" and filtered_principals:
                            for principal in filtered_principals:
                                if statement.Condition and statement.Condition.dict():
                                    # Ignoring condition checks since they will get reviewed in other
                                    # rules and future improvements
                                    pass
                                else:
                                    self.add_failure_to_result(
                                        result,
                                        self.REASON.format(logical_id),
                                        resource_ids={logical_id},
                                        context={
                                            "config": self._config,
                                            "extras": extras,
                                            "logical_id": logical_id,
                                            "resource": resource,
                                            "statement": statement,
                                            "principal": principal,
                                        },
                                    )
        return result
