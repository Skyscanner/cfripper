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
from ..model.enums import RuleRisk
from ..model.rule import Rule


class S3BucketPublicReadWriteAclRule(Rule):
    REASON = "S3 Bucket {} should not have a public read-write acl"
    RISK_VALUE = RuleRisk.HIGH

    def invoke(self, cfmodel):
        for logical_id, resource in cfmodel.Resources.items():
            if (
                resource.Type == "AWS::S3::Bucket"
                and hasattr(resource, "Properties")
                and resource.Properties.get("AccessControl") == "PublicReadWrite"
            ):
                self.add_failure(type(self).__name__, self.REASON.format(logical_id))
