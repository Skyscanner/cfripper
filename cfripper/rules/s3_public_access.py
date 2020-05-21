__all__ = ["S3BucketPublicReadAclAndListStatementRule", "S3BucketPublicReadWriteAclRule"]

import logging
import re
from typing import Dict, Optional

from pycfmodel.model.cf_model import CFModel
from pycfmodel.model.resources.s3_bucket_policy import S3BucketPolicy

from cfripper.model.enums import RuleGranularity, RuleRisk
from cfripper.model.result import Result
from cfripper.rules.base_rules import Rule

logger = logging.getLogger(__file__)


class S3BucketPublicReadAclAndListStatementRule(Rule):
    # TODO: refactor regex to regex file.
    """
    Checks if any S3 bucket policy has a public read ACL and `List` permission in the bucket policy.

    Fix:
        Unless the bucket is hosting static content and needs to be accessed publicly,
        these bucket policies should be locked down.
    """

    GRANULARITY = RuleGranularity.RESOURCE
    REASON = "S3 Bucket {} should not have a public read acl and list bucket statement"

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, S3BucketPolicy) and resource.Properties.PolicyDocument.allowed_actions_with(
                re.compile(r"^s3:L.*$")
            ):
                bucket_name = resource.Properties.Bucket
                if "UNDEFINED_PARAM_" in bucket_name:
                    bucket_name = bucket_name[len("UNDEFINED_PARAM_") :]
                bucket = cfmodel.Resources.get(bucket_name)
                if bucket and bucket.Properties.get("AccessControl") == "PublicRead":
                    self.add_failure_to_result(result, self.REASON.format(logical_id), resource_ids={logical_id})
        return result


class S3BucketPublicReadWriteAclRule(Rule):
    """
    Checks if any S3 bucket policy has access control set to `PublicReadWrite`.

    Risk:
        Unless required, S3 buckets should not have Public Write available on a bucket. This allows anyone
        to write any objects to your S3 bucket.

    Fix:
        Remove any configuration that looks like `"AccessControl": "PublicReadWrite"` from your S3 bucket policy.
    """

    GRANULARITY = RuleGranularity.RESOURCE
    REASON = "S3 Bucket {} should not have a public read-write acl"
    RISK_VALUE = RuleRisk.HIGH

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()
        for logical_id, resource in cfmodel.Resources.items():
            if (
                resource.Type == "AWS::S3::Bucket"
                and hasattr(resource, "Properties")
                and resource.Properties.get("AccessControl") == "PublicReadWrite"
            ):
                self.add_failure_to_result(result, self.REASON.format(logical_id), resource_ids={logical_id})
        return result
