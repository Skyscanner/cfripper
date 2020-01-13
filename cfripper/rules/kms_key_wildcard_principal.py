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
__all__ = ["KMSKeyWildcardPrincipal"]
import logging
import re

from pycfmodel.model.cf_model import CFModel
from pycfmodel.model.resources.kms_key import KMSKey

from cfripper.model.enums import RuleGranularity
from cfripper.model.rule import Rule

logger = logging.getLogger(__file__)


class KMSKeyWildcardPrincipal(Rule):
    """
    Check for wildcards in principals in KMS Policies.
    """

    GRANULARITY = RuleGranularity.RESOURCE

    REASON = "KMS Key policy {} should not allow wildcard principals"
    CONTAINS_WILDCARD_PATTERN = re.compile(r"^(\w*:)?\*$")

    def invoke(self, cfmodel: CFModel):
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
                                    self.add_failure(
                                        type(self).__name__, self.REASON.format(logical_id), resource_ids={logical_id}
                                    )
