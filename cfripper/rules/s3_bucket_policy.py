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
__all__ = ["S3BucketPolicyPrincipalRule"]
import logging

from pycfmodel.model.resources.s3_bucket_policy import S3BucketPolicy

from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.utils import get_account_id_from_principal
from cfripper.rules.base_rules import PrincipalCheckingRule

logger = logging.getLogger(__file__)


class S3BucketPolicyPrincipalRule(PrincipalCheckingRule):
    """
    Checks for non-whitelisted principals in S3 bucket policies.

    Risk:
        This is designed to block unintended access from third party accounts to your buckets.

    Fix:
        All principals connected to S3 Bucket Policies should be known. CFRipper checks that **all** principals meet
        the requirements expected. The list of valid accounts is defined in `valid_principals`, which is set in the config.
    """

    GRANULARITY = RuleGranularity.RESOURCE
    REASON = "S3 Bucket {} policy has non-whitelisted principals {}"
    RULE_MODE = RuleMode.BLOCKING
    RISK_VALUE = RuleRisk.HIGH

    def invoke(self, cfmodel):
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, S3BucketPolicy):
                for statement in resource.Properties.PolicyDocument._statement_as_list():
                    for principal in statement.get_principal_list():
                        account_id = get_account_id_from_principal(principal)
                        if not account_id:
                            continue
                        if account_id not in self.valid_principals:
                            if statement.Condition and statement.Condition.dict():
                                logger.warning(
                                    f"Not adding {type(self).__name__} failure in {logical_id} "
                                    f"because there are conditions: {statement.Condition}"
                                )
                            else:
                                self.add_failure(
                                    type(self).__name__,
                                    self.REASON.format(logical_id, account_id),
                                    resource_ids={logical_id},
                                )
