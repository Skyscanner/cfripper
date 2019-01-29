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


from cfripper.model.rule_processor import Rule
from cfripper.config.logger import get_logger

logger = get_logger()


class S3BucketPublicReadAclAndListStatementRule(Rule):

    REASON = "S3 Bucket {} should not have a public read acl and list bucket statement"
    MONITOR_MODE = True

    def invoke(self, resources, parameters):
        # Get all bucket policies and filter to get the ones that allow list actions
        bucket_policies = []
        for policy in resources.get("AWS::S3::BucketPolicy", []):
            if any(policy.policy_document.wildcard_allowed_actions(pattern=r"^s3:L.*$")):
                bucket_policies.append(policy.bucket["Ref"])

        # Check if bucket policies exist
        if bucket_policies:
            # Get S3 buckets
            buckets = resources.get("AWS::S3::Bucket", [])
            for resource in buckets:
                try:
                    if resource.access_control == "PublicRead" and resource.logical_id in bucket_policies:
                        self.add_failure(
                            type(self).__name__,
                            self.REASON.format(resource.logical_id),
                        )
                except AttributeError:
                    logger.info("No access control on bucket")
