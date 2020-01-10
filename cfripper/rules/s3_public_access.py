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
__all__ = ["S3BucketPublicReadAclAndListStatementRule", "S3BucketPublicReadWriteAclRule"]

import logging
import re

from pycfmodel.model.resources.s3_bucket_policy import S3BucketPolicy

from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.rule import Rule

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
    RULE_MODE = RuleMode.DEBUG

    def invoke(self, cfmodel):
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, S3BucketPolicy) and resource.Properties.PolicyDocument.allowed_actions_with(
                re.compile(r"^s3:L.*$")
            ):
                bucket_name = resource.Properties.Bucket
                if "UNDEFINED_PARAM_" in bucket_name:
                    bucket_name = bucket_name[len("UNDEFINED_PARAM_") :]
                bucket = cfmodel.Resources.get(bucket_name)
                if bucket and bucket.Properties.get("AccessControl") == "PublicRead":
                    self.add_failure(type(self).__name__, self.REASON.format(logical_id), resource_ids={logical_id})


class S3BucketPublicReadWriteAclRule(Rule):
    """
    Checks if any S3 bucket policy has access control set to `PublicReadWrite`.
    """

    GRANULARITY = RuleGranularity.RESOURCE
    REASON = "S3 Bucket {} should not have a public read-write acl"
    RISK_VALUE = RuleRisk.HIGH

    def invoke(self, cfmodel):
        for logical_id, resource in cfmodel.Resources.items():
            if (
                resource.Type == "AWS::S3::Bucket"
                and hasattr(resource, "Properties")
                and resource.Properties.get("AccessControl") == "PublicReadWrite"
            ):
                self.add_failure(type(self).__name__, self.REASON.format(logical_id), resource_ids={logical_id})
