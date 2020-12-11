__all__ = ["S3BucketPolicyPrincipalRule"]
import logging
from typing import Dict, Optional

from pycfmodel.model.resources.s3_bucket_policy import S3BucketPolicy

from cfripper.model.enums import RuleGranularity, RuleRisk
from cfripper.model.result import Result
from cfripper.model.utils import get_account_id_from_principal
from cfripper.rules.base_rules import PrincipalCheckingRule, ResourceSpecificRule

logger = logging.getLogger(__file__)


class S3BucketPolicyPrincipalRule(PrincipalCheckingRule, ResourceSpecificRule):
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
    RISK_VALUE = RuleRisk.HIGH
    RESOURCE_TYPES = (S3BucketPolicy,)

    def resource_invoke(self, resource: S3BucketPolicy, logical_id: str, extras: Optional[Dict] = None) -> Result:
        result = Result()

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
                        self.add_failure_to_result(
                            result, self.REASON.format(logical_id, account_id), resource_ids={logical_id},
                        )
        return result
