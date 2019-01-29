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


from cfripper.config.logger import get_logger
from cfripper.model.rule_processor import Rule

logger = get_logger()


class IAMRolesOverprivilegedRule(Rule):

    def invoke(self, resources, parameters):
        for resource in resources.get("AWS::IAM::Role", []):
            self.process_resource(resource.logical_id, resource)

    def process_resource(self, logical_name, properties):
        if not properties:
            return

        self.check_managed_policies(logical_name, properties.managed_policy_arns)
        self.check_inline_policies(logical_name, properties.policies)

    def check_managed_policies(self, logical_name, managed_policy_arns):
        """Run the managed policies against a blacklist."""

        if not managed_policy_arns:
            return

        for managed_policy_arn in managed_policy_arns:
            if managed_policy_arn in self._config.FORBIDDEN_MANAGED_POLICY_ARNS:
                reason = "Role {} has forbidden Managed Policy {}".format(
                    logical_name,
                    managed_policy_arn,
                )
                self.add_failure(type(self).__name__, reason)

    def check_inline_policies(self, logical_name, policies):
        """Check conditional and non-conditional inline policies."""

        if not policies:
            return

        for policy in policies:
            self.check_inline_policy(
                logical_name,
                policy.policy_name,
                policy.policy_document,
            )

    def check_inline_policy(self, logical_name_of_resource, policy_name, inline_policy):
        star_resource_statements = inline_policy.star_resource_statements()
        for statement in star_resource_statements:
            self.__check_actions(logical_name_of_resource, policy_name, statement)

    def __check_actions(self, logical_name_of_resource, policy_name, statement):
        """Check if there's a * action for a resource in the blacklist."""
        if statement.effect and statement.effect == "Deny":
            return
        for action in statement.get_action_list():
            for prefix in self._config.FORBIDDEN_RESOURCE_STAR_ACTION_PREFIXES:
                if action.startswith(prefix):
                    reason = "Role \"{}\" contains an insecure permission \"{}\" in policy \"{}\"".format(
                        logical_name_of_resource,
                        action, policy_name,
                    )
                    self.add_failure(type(self).__name__, reason)
