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

from pycfmodel.model.resources.s3_bucket_policy import S3BucketPolicy

from cfripper.model.enums import RuleMode
from cfripper.model.utils import get_account_id_from_principal

from ..model.principal_checking_rule import PrincipalCheckingRule

logger = logging.getLogger(__file__)


class S3CrossAccountTrustRule(PrincipalCheckingRule):

    REASON = "{} has forbidden cross-account policy allow with {} for an S3 bucket."

    def invoke(self, cfmodel):
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, S3BucketPolicy):
                for statement in resource.Properties.PolicyDocument._statement_as_list():
                    if statement.Effect == "Allow":
                        for principal in statement.get_principal_list():
                            account_id = get_account_id_from_principal(principal)
                            if account_id not in self.valid_principals:
                                if statement.Condition and statement.Condition.dict():
                                    logger.warning(
                                        f"Not adding {type(self).__name__} failure in {logical_id} "
                                        f"because there are conditions: {statement.Condition}"
                                    )
                                elif "GETATT" in principal or "UNDEFINED_" in principal:
                                    self.add_failure(
                                        type(self).__name__,
                                        self.REASON.format(logical_id, principal),
                                        rule_mode=RuleMode.DEBUG,
                                    )
                                else:
                                    self.add_failure(type(self).__name__, self.REASON.format(logical_id, principal))
