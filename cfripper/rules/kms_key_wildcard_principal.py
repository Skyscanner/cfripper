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
    """

    GRANULARITY = RuleGranularity.RESOURCE

    REASON = "KMS Key policy {} should not allow wildcard principals"
    CONTAINS_WILDCARD_PATTERN = re.compile(r"^(\w*:)?\*$")

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, KMSKey):
                for statement in resource.Properties.KeyPolicy._statement_as_list():
                    if statement.Effect == "Allow" and statement.principals_with(self.CONTAINS_WILDCARD_PATTERN):
                        for principal in statement.get_principal_list():
                            if self.CONTAINS_WILDCARD_PATTERN.match(principal):
                                if statement.Condition and statement.Condition.dict():
                                    logger.warning(
                                        f"Not adding {type(self).__name__} failure in {logical_id} "
                                        f"because there are conditions: {statement.Condition}"
                                    )
                                else:
                                    self.add_failure_to_result(
                                        result, self.REASON.format(logical_id), resource_ids={logical_id}
                                    )
        return result
