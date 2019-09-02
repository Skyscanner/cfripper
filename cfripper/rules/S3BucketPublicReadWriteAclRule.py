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


class S3BucketPublicReadWriteAclRule(Rule):

    REASON = "S3 Bucket {} should not have a public read-write acl"
    RISK_VALUE = Rule.HIGH

    def invoke(self, resources, parameters):
        for resource in resources.get("AWS::S3::Bucket", []):
            try:
                if resource.access_control == "PublicReadWrite":
                    self.add_failure(
                        type(self).__name__,
                        self.REASON.format(resource.logical_id),
                    )
            except AttributeError:
                logger.info("No access control on bucket")
