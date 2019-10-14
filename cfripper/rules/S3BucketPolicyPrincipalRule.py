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
import logging
import re


from ..model.enums import RuleMode, RuleRisk
from ..model.rule import Rule

logger = logging.getLogger(__file__)


class S3BucketPolicyPrincipalRule(Rule):

    REASON = "S3 Bucket {} policy has non-whitelisted principals {}"
    RULE_MODE = RuleMode.BLOCKING
    RISK_VALUE = RuleRisk.HIGH
    PATTERN = r"arn:aws:iam::(\d*):.*"

    def invoke(self, cfmodel):
        for logical_id, resource in cfmodel.Resources.items():
            if resource.Type == "AWS::S3::BucketPolicy":
                for statement in resource.Properties.PolicyDocument._statement_as_list():
                    for principal in statement.get_principal_list():
                        self.check_account_number(logical_id, principal)

    def check_account_number(self, logical_id, principal):
        account_id_match = re.match(self.PATTERN, principal)
        if account_id_match:
            account_id = account_id_match.group(1)
            if self._config.aws_principals and account_id not in self._config.aws_principals:
                self.add_failure(type(self).__name__, self.REASON.format(logical_id, account_id))
