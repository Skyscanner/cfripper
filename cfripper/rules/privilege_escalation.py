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
from pycfmodel.model.resources.iam_policy import IAMPolicy

from ..model.rule import Rule


class PrivilegeEscalationRule(Rule):

    REASON = "{} has blacklisted IAM action {}"
    IAM_BLACKLIST = set(
        action.lower()
        for action in [
            "iam:CreateAccessKey",
            "iam:CreateLoginProfile",
            "iam:UpdateLoginProfile",
            "iam:AttachUserPolicy",
            "iam:AttachGroupPolicy",
            "iam:AttachRolePolicy",
            "iam:PutUserPolicy",
            "iam:PutGroupPolicy",
            "iam:PutRolePolicy",
            "iam:CreatePolicy",
            "iam:AddUserToGroup",
            "iam:UpdateAssumeRolePolicy",
            "iam:CreatePolicyVersion",
            "iam:SetDefaultPolicyVersion",
        ]
    )

    def invoke(self, cfmodel):
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, IAMPolicy):
                policy_actions = set(action.lower() for action in resource.Properties.PolicyDocument.get_iam_actions())
                for violation in policy_actions.intersection(self.IAM_BLACKLIST):
                    self.add_failure(type(self).__name__, self.REASON.format(logical_id, violation))
