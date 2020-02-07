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
__all__ = ["PolicyOnUserRule"]

from typing import Dict, Optional

from pycfmodel.model.cf_model import CFModel
from pycfmodel.model.resources.iam_policy import IAMPolicy

from cfripper.model.enums import RuleGranularity, RuleMode
from cfripper.model.result import Result
from cfripper.rules.base_rules import Rule


class PolicyOnUserRule(Rule):
    """
    Checks if any IAM policy is applied to a group and not a user.
    """

    GRANULARITY = RuleGranularity.RESOURCE
    REASON = "IAM policy {} should not apply directly to users. Should be on group"
    RULE_MODE = RuleMode.MONITOR

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, IAMPolicy) and resource.Properties.Users:
                self.add_failure_to_result(result, self.REASON.format(logical_id), resource_ids={logical_id})
        return result
