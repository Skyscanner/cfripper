"""
Copyright 2019 Skyscanner Ltd

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
"""
from ..model.rule import Rule


class S3CrossAccountTrustRule(Rule):

    REASON = "{} has forbidden cross-account policy allow with {} for an S3 bucket."

    def invoke(self, cfmodel):
        for logical_id, resource in cfmodel.Resources.items():
            if resource.Type == "AWS::S3::BucketPolicy":
                for statement in resource.Properties.PolicyDocument._statement_as_list():
                    if statement.Effect == "Allow":
                        for principal in statement.get_principal_list():
                            if self._config.aws_account_id and self._config.aws_account_id not in principal:
                                self.add_failure(type(self).__name__, self.REASON.format(logical_id, principal))
