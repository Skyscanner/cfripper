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

from pycfmodel.model.resources.iam_role import IAMRole

from ..config.regex import REGEX_CROSS_ACCOUNT_ROOT
from ..model.enums import RuleGranularity, RuleMode
from ..model.rule import Rule


class CrossAccountTrustRule(Rule):

    REASON = "{} has forbidden cross-account trust relationship with {}"
    ROOT_PATTERN = re.compile(REGEX_CROSS_ACCOUNT_ROOT)
    GRANULARITY = RuleGranularity.RESOURCE

    def invoke(self, cfmodel):
        not_has_account_id = re.compile(rf"^((?!{self._config.aws_account_id}).)*$")
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, IAMRole):
                for principal in resource.Properties.AssumeRolePolicyDocument.allowed_principals_with(
                    self.ROOT_PATTERN
                ):
                    self.add_failure(
                        type(self).__name__, self.REASON.format(logical_id, principal), resource_ids={logical_id}
                    )

                if self._config.aws_account_id:
                    for principal in resource.Properties.AssumeRolePolicyDocument.allowed_principals_with(
                        not_has_account_id
                    ):
                        if not principal.endswith(".amazonaws.com"):  # Checks if principal is an AWS service
                            if "GETATT" in principal or "UNDEFINED_" in principal:
                                self.add_failure(
                                    type(self).__name__,
                                    self.REASON.format(logical_id, principal),
                                    resource_ids={logical_id},
                                    rule_mode=RuleMode.DEBUG,
                                )
                            else:
                                self.add_failure(
                                    type(self).__name__,
                                    self.REASON.format(logical_id, principal),
                                    resource_ids={logical_id},
                                )
