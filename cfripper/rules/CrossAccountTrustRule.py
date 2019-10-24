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
import re

from ..config.regex import REGEX_CROSS_ACCOUNT_ROOT
from ..model.rule import Rule
from ..model.enums import RuleGranularity


class CrossAccountTrustRule(Rule):

    REASON = "{} has forbidden cross-account trust relationship with {}"
    ROOT_PATTERN = re.compile(REGEX_CROSS_ACCOUNT_ROOT)
    GRANULARITY = RuleGranularity.RESOURCE

    def invoke(self, cfmodel):
        not_has_account_id = re.compile(rf"^((?!{self._config.aws_account_id}).)*$")
        for logical_id, resource in cfmodel.Resources.items():
            if resource.Type == "AWS::IAM::Role":
                for principal in resource.Properties.AssumeRolePolicyDocument.allowed_principals_with(
                    self.ROOT_PATTERN
                ):
                    self.add_failure(
                        type(self).__name__, self.REASON.format(logical_id, principal), resource_ids={logical_id}
                    )

                for principal in resource.Properties.AssumeRolePolicyDocument.allowed_principals_with(
                    not_has_account_id
                ):
                    self.add_failure(
                        type(self).__name__, self.REASON.format(logical_id, principal), resource_ids={logical_id}
                    )
