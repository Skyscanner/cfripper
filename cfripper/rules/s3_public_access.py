__all__ = ["S3BucketPublicReadAclAndListStatementRule", "S3BucketPublicReadWriteAclRule", "S3BucketPublicReadAclRule"]

import logging
import re
from typing import Dict, Optional

from pycfmodel.model.cf_model import CFModel
from pycfmodel.model.resources.s3_bucket import S3Bucket
from pycfmodel.model.resources.s3_bucket_policy import S3BucketPolicy

from cfripper.model.enums import RuleGranularity, RuleRisk
from cfripper.model.result import Result
from cfripper.rules.base_rules import ResourceSpecificRule, Rule

logger = logging.getLogger(__file__)


class S3BucketPublicReadAclAndListStatementRule(Rule):
    # TODO: refactor regex to regex file.
    """
    Checks if any S3 bucket policy has a public read ACL and `List` permission in the bucket policy.

    Fix:
        Unless the bucket is hosting static content and needs to be accessed publicly,
        these bucket policies should be locked down.

    Filters context:
        | Parameter     | Type               | Description                                                    |
        |:-------------:|:------------------:|:--------------------------------------------------------------:|
        |`config`       | str                | `config` variable available inside the rule                    |
        |`extras`       | str                | `extras` variable available inside the rule                    |
        |`logical_id`   | str                | ID used in Cloudformation to refer the resource being analysed |
        |`resource`     | `S3BucketPolicy`   | Resource that is being addressed                               |
        |`bucket_name`  | str                | Name of the S3 bucket being analysed                           |
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
                if not isinstance(bucket_name, str):
                    logger.warning(f"Not adding {type(self).__name__} failure in {logical_id} – try resolving?")
                    continue
                if "UNDEFINED_PARAM_" in bucket_name:
                    bucket_name = bucket_name[len("UNDEFINED_PARAM_") :]

                bucket = cfmodel.Resources.get(bucket_name)
                if bucket and bucket.Properties.AccessControl == "PublicRead":
                    self.add_failure_to_result(
                        result,
                        self.REASON.format(logical_id),
                        resource_ids={logical_id},
                        resource_types={resource.Type},
                        context={
                            "config": self._config,
                            "extras": extras,
                            "logical_id": logical_id,
                            "resource": resource,
                            "bucket_name": bucket_name,
                        },
                    )
        return result


class S3BucketPublicReadWriteAclRule(ResourceSpecificRule):
    """
    Checks if any S3 bucket policy has access control set to `PublicReadWrite`.

    Risk:
        Unless required, S3 buckets should not have Public Write available on a bucket. This allows anyone
        to write any objects to your S3 bucket.

    Fix:
        Remove any configuration that looks like `"AccessControl": "PublicReadWrite"` from your S3 bucket policy.

    Filters context:
        | Parameter     | Type               | Description                                                    |
        |:-------------:|:------------------:|:--------------------------------------------------------------:|
        |`config`       | str                | `config` variable available inside the rule                    |
        |`extras`       | str                | `extras` variable available inside the rule                    |
        |`logical_id`   | str                | ID used in Cloudformation to refer the resource being analysed |
        |`resource`     | `S3Bucket`         | S3 Bucket that is being addressed                              |
    """

    GRANULARITY = RuleGranularity.RESOURCE
    REASON = "S3 Bucket {} should not have a public read-write acl"
    RESOURCE_TYPES = (S3Bucket,)
    RISK_VALUE = RuleRisk.HIGH

    def resource_invoke(self, resource: S3Bucket, logical_id: str, extras: Optional[Dict] = None) -> Result:
        result = Result()
        if resource.Properties.AccessControl == "PublicReadWrite":
            self.add_failure_to_result(
                result,
                self.REASON.format(logical_id),
                resource_ids={logical_id},
                resource_types={resource.Type},
                context={"config": self._config, "extras": extras, "logical_id": logical_id, "resource": resource},
            )
        return result


class S3BucketPublicReadAclRule(ResourceSpecificRule):
    """
    Checks if any S3 bucket policy has access control set to `PublicRead`.

    Risk:
        Unless the bucket is hosting static content, S3 buckets should not have Public Read available on a bucket.
        This allows anyone to read any objects to your S3 bucket.

    Fix:
        Remove any configuration that looks like `"AccessControl": "PublicRead"` from your S3 bucket policy.

    Filters context:
        | Parameter     | Type               | Description                                                    |
        |:-------------:|:------------------:|:--------------------------------------------------------------:|
        |`config`       | str                | `config` variable available inside the rule                    |
        |`extras`       | str                | `extras` variable available inside the rule                    |
        |`logical_id`   | str                | ID used in Cloudformation to refer the resource being analysed |
        |`resource`     | `S3Bucket`         | S3 Bucket that is being addressed                              |
    """

    GRANULARITY = RuleGranularity.RESOURCE
    REASON = "S3 Bucket {} should not have a public-read acl"
    RESOURCE_TYPES = (S3Bucket,)
    RISK_VALUE = RuleRisk.HIGH

    def resource_invoke(self, resource: S3Bucket, logical_id: str, extras: Optional[Dict] = None) -> Result:
        result = Result()
        if resource.Properties.AccessControl == "PublicRead":
            self.add_failure_to_result(
                result,
                self.REASON.format(logical_id),
                resource_ids={logical_id},
                resource_types={resource.Type},
                context={"config": self._config, "extras": extras, "logical_id": logical_id, "resource": resource},
            )
        return result
