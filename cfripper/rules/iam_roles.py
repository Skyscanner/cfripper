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
__all__ = ["IAMRolesOverprivilegedRule", "IAMRoleWildcardActionOnPolicyRule"]
from pycfmodel.model.resources.iam_managed_policy import IAMManagedPolicy
from pycfmodel.model.resources.iam_role import IAMRole

from cfripper.config.regex import REGEX_IS_STAR, REGEX_WILDCARD_POLICY_ACTION
from cfripper.model.enums import RuleGranularity
from cfripper.model.rule import Rule, RuleMode


class IAMRolesOverprivilegedRule(Rule):
    """
    Rule that checks for wildcards in resources for a set of actions and restricts managed policies.
    """

    GRANULARITY = RuleGranularity.RESOURCE

    def invoke(self, cfmodel):
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, IAMRole):
                self.check_managed_policies(logical_id, resource)
                self.check_inline_policies(logical_id, resource)

    def check_managed_policies(self, logical_id, role):
        """Run the managed policies against a blacklist."""
        if not role.Properties.ManagedPolicyArns:
            return

        for managed_policy_arn in role.Properties.ManagedPolicyArns:
            if managed_policy_arn in self._config.forbidden_managed_policy_arns:
                self.add_failure(
                    type(self).__name__,
                    f"Role {logical_id} has forbidden Managed Policy {managed_policy_arn}",
                    resource_ids={logical_id},
                )

    def check_inline_policies(self, logical_id, role):
        """Check conditional and non-conditional inline policies."""
        if not role.Properties.Policies:
            return

        for policy in role.Properties.Policies:
            for statement in policy.PolicyDocument.statements_with(REGEX_IS_STAR):
                if statement.Effect and statement.Effect == "Allow":
                    for action in statement.get_action_list():
                        for prefix in self._config.forbidden_resource_star_action_prefixes:
                            if action.startswith(prefix):
                                self.add_failure(
                                    type(self).__name__,
                                    f"Role '{logical_id}' contains an insecure permission '{action}' in policy "
                                    f"'{policy.PolicyName}'",
                                    resource_ids={logical_id},
                                )


class IAMRoleWildcardActionOnPolicyRule(Rule):
    """
    Checks for use of wildcard characters in all IAM Role policies (including AssumeRolePolicyDocument)
    and AWS Managed Policies
    (https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html).
    """

    GRANULARITY = RuleGranularity.RESOURCE
    REASON = "IAM role {} should not allow a `*` action on its {}"
    RULE_MODE = RuleMode.DEBUG

    def invoke(self, cfmodel):
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, IAMRole):
                # check AssumeRolePolicyDocument.
                if resource.Properties.AssumeRolePolicyDocument.allowed_actions_with(REGEX_WILDCARD_POLICY_ACTION):
                    self.add_failure(
                        type(self).__name__,
                        self.REASON.format(logical_id, "AssumeRolePolicy"),
                        resource_ids={logical_id},
                    )

                # check other policies of the IAM role.
                if resource.Properties.Policies:
                    for policy in resource.Properties.Policies:
                        if policy.PolicyDocument.allowed_actions_with(REGEX_WILDCARD_POLICY_ACTION):
                            self.add_failure(
                                type(self).__name__,
                                self.REASON.format(logical_id, f"{policy.PolicyName} policy"),
                                resource_ids={logical_id},
                            )

            # check AWS::IAM::ManagedPolicy.
            elif isinstance(resource, IAMManagedPolicy) and resource.Properties.PolicyDocument.allowed_actions_with(
                REGEX_WILDCARD_POLICY_ACTION
            ):
                self.add_failure(
                    type(self).__name__,
                    self.REASON.format(logical_id, "AWS::IAM::ManagedPolicy"),
                    resource_ids={logical_id},
                )
