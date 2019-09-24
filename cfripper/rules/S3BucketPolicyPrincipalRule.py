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


class S3BucketPolicyPrincipalRule(Rule):

    REASON = "S3 Bucket {} policy has non-whitelisted principals {}"
    RULE_MODE = Rule.BLOCKING
    RISK_VALUE = Rule.HIGH
    PATTERN = r"arn:aws:iam::(\d*):.*"

    def invoke(self, resources, parameters):
        for resource in resources.get("AWS::S3::BucketPolicy", []):
            for statement in resource.policy_document.statements:
                if statement.condition:
                    continue
                for principal in statement.principal:
                    self.check_account_number(principal, resource.logical_id)

    def check_account_number(self, p, logical_id):
        for principal in p.principals:
            if not isinstance(principal, str):
                logger.warn(
                    f"{type(self).__name__}/{self._config.stack_name}/{self._config.service_name}"
                    " - Skipping validation: principal is possibly a function."
                )
                continue
            account_id_match = re.match(self.PATTERN, principal)
            if not account_id_match:
                continue
            account_id = account_id_match.group(1)
            if self._config.aws_principals and account_id not in self._config.aws_principals:
                self.add_failure(type(self).__name__, self.REASON.format(logical_id, account_id))
