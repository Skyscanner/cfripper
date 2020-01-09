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
__all__ = ["ManagedPolicyOnUserRule"]
from pycfmodel.model.cf_model import CFModel
from pycfmodel.model.resources.iam_managed_policy import IAMManagedPolicy

from cfripper.model.enums import RuleGranularity, RuleMode
from cfripper.model.rule import Rule


class ManagedPolicyOnUserRule(Rule):
    """
    Checks if any IAM managed policy is applied to a group and not a user.
    """

    REASON = "IAM managed policy {} should not apply directly to users. Should be on group"
    RULE_MODE = RuleMode.MONITOR
    GRANULARITY = RuleGranularity.RESOURCE

    def invoke(self, cfmodel: CFModel):
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, IAMManagedPolicy) and resource.Properties.Users:
                self.add_failure(type(self).__name__, self.REASON.format(logical_id), resource_ids={logical_id})
