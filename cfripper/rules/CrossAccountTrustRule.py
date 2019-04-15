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


import re
from cfripper.config.logger import get_logger
from cfripper.model.rule_processor import Rule

logger = get_logger()


class CrossAccountTrustRule(Rule):

    REASON = "{} has forbidden cross-account trust relationship with {}"
    MONITOR_MODE = False
    ROOT_PATTERN = re.compile(r"arn:aws:iam::\d*:root")

    def invoke(self, resources, parameters):
        for resource in resources.get("AWS::IAM::Role", []):
            arpd = resource.assume_role_policy_document
            for statement in arpd.statements:
                aws_principals = self.get_aws_principals(statement) or []
                self.check_principals(aws_principals, resource.logical_id)

    def check_principals(self, principals, logical_id):
        for principal in principals:
            cross_account = self._config.account_id and self._config.account_id not in principal

            if not isinstance(principal, str):
                logger.warn(
                    f"{type(self).__name__}/{self._config.stack_name}/{self._config.service_name} \
                    - Skipping validation: principal is possibly a function."
                )
                continue

            if self.ROOT_PATTERN.match(principal) or cross_account:
                self.add_failure(
                    type(self).__name__,
                    self.REASON.format(
                        logical_id,
                        principal,
                    ),
                )

    def get_aws_principals(self, statement):
        for principal in statement.principal:
            if principal._type == "AWS":
                return principal.principals
        return None
