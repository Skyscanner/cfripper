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
from pycfmodel.model.resources.iam_role import IAMRole

from ..config.regex import REGEX_WILDCARD_POLICY_ACTION
from ..model.rule import Rule


class IAMRoleWildcardActionOnPermissionsPolicyRule(Rule):

    REASON = "IAM role {} should not allow * action on its permissions policy {}"

    def invoke(self, cfmodel):
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, IAMRole):
                for policy in resource.Properties.Policies:
                    if policy.PolicyDocument.allowed_actions_with(REGEX_WILDCARD_POLICY_ACTION):
                        self.add_failure(type(self).__name__, self.REASON.format(logical_id, policy.PolicyName))
