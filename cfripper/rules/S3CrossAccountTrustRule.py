"""
Copyright 2019 Skyscanner Ltd

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


class S3CrossAccountTrustRule(Rule):

    REASON = "{} has forbidden cross-account policy allow with {} for an S3 bucket."
    MONITOR_MODE = False

    def invoke(self, resources, parameters):
        for resource in resources.get("AWS::S3::BucketPolicy", []):
            for statement in resource.policy_document.statements:
                if statement.effect == "Allow":
                    aws_principals = self.get_aws_principals(statement) or []
                    self.check_principals(aws_principals, resource.logical_id)

    def check_principals(self, principals, logical_id):
        for principal in principals:
            cross_account = (
                self._config.account_id and self._config.account_id not in principal
            )

            if not isinstance(principal, str):
                logger.warn(
                    f"{type(self).__name__}/{self._config.stack_name}/{self._config.service_name} \
                    - Skipping validation: principal is possibly a function."
                )
                continue

            if cross_account:
                self.add_failure(type(self).__name__, self.REASON.format(logical_id, principal))

    def get_aws_principals(self, statement):
        for principal in statement.principal:
            if principal._type == "AWS" and not principal.has_wildcard_principals():
                return principal.principals
        return None
