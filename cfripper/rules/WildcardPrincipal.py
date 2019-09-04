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
import logging
import re

from cfripper.model.rule_processor import Rule

logger = logging.getLogger(__file__)

POLICY_DOCUMENT_TYPES = ("policy_document", "key_policy", "assume_role_policy_document")


class GenericWildcardPrincipal(Rule):

    REASON_WILCARD_PRINCIPAL = "{} should not allow wildcard in principals or account-wide principals (principal: '{}')"
    REASON_NOT_ALLOWED_PRINCIPAL = "{} contains an unknown principal: {}"
    RULE_MODE = Rule.MONITOR
    IAM_PATTERN = r"arn:aws:iam::(\d*|\*):.*"

    FULL_REGEX = r"^((\w*:){0,1}\*|arn:aws:iam::(\d*|\*):.*)$"

    def invoke(self, resources, parameters):
        for resource_list in resources.values():
            for resource in resource_list:
                # Resource has policies
                for policy in getattr(resource, "policies", []):
                    self.check_for_wildcards(
                        resource=policy, resource_id=getattr(policy, "policy_name", resource.logical_id)
                    )
                # Resouce is a policy
                self.check_for_wildcards(resource=resource, resource_id=resource.logical_id)

    def check_for_wildcards(self, resource, resource_id):
        if resource is None:
            return

        for policy_document in POLICY_DOCUMENT_TYPES:
            if not hasattr(resource, policy_document):
                continue

            for statement in getattr(resource, policy_document).wildcard_allowed_principals(pattern=self.FULL_REGEX):
                for principal_list in statement.principal:
                    self.check_principals(principal_list, statement, resource_id)

    def resource_is_whitelisted(self, logical_id):
        return logical_id in self._config.get_wildcard_principal_exemption_resource_list()

    def validate_account_id(self, account_id, logical_id):

        if (
            self._config.aws_principals
            and account_id not in self._config.aws_principals
            and not self.resource_is_whitelisted(logical_id)
        ):
            self.add_failure(type(self).__name__, self.REASON_NOT_ALLOWED_PRINCIPAL.format(logical_id, account_id))
            logger.info(
                f"{type(self).__name__}/{self._config.stack_name}/{self._config.service_name}"
                f"{self.REASON_NOT_ALLOWED_PRINCIPAL.format(logical_id, account_id)}"
            )

    def check_principals(self, principal_list, statement, logical_id):

        for principal in principal_list.principals:
            if not isinstance(principal, str):
                logger.warn(
                    f"{type(self).__name__}/{self._config.stack_name}/{self._config.service_name}"
                    " - Skipping validation: principal is possibly a function."
                )
                continue

            # Check if account ID is allowed
            account_id_match = re.match(self.IAM_PATTERN, principal)
            if account_id_match:
                self.validate_account_id(account_id=account_id_match.group(1), logical_id=logical_id)
            # Check for other wildcards
            if not re.match(self.FULL_REGEX, principal):
                # Need to check this because pycfmodel currently returns Statements with *
                # No matter which pattern is passed
                continue

            if not statement.condition and not self.resource_is_whitelisted(logical_id):
                self.add_failure(type(self).__name__, self.REASON_WILCARD_PRINCIPAL.format(logical_id, principal))
                logger.info(
                    f"{type(self).__name__}/{self._config.stack_name}/{self._config.service_name}"
                    f"{self.REASON_WILCARD_PRINCIPAL.format(logical_id, principal)}"
                )
