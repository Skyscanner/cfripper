"""
Copyright 2018 Skyscanner Ltd

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
"""


from cfripper.model.rule_processor import Rule


class PrivilegeEscalationRule(Rule):

    REASON = "{} has blacklisted IAM action {}"
    MONITOR_MODE = False
    IAM_BLACKLIST = set(
        [
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

    def invoke(self, resources, parameters):
        for resource in resources.get("AWS::IAM::Policy", []):
            actions = set(map(lambda x: x.lower(), resource.policy_document.get_iam_actions()))
            intersection = actions.intersection(set(map(lambda x: x.lower(), self.IAM_BLACKLIST)))

            if len(intersection):
                for violation in intersection:
                    self.add_failure(
                        type(self).__name__,
                        self.REASON.format(
                            resource.logical_id,
                            violation,
                        ),
                    )
