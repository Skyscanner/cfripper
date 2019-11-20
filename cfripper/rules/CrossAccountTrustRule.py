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
import logging
import re

from pycfmodel.model.resources.iam_role import IAMRole

from cfripper.model.utils import get_account_id_from_principal
from cfripper.rules.base_rules import CrossAccountCheckingRule

from ..config.regex import REGEX_CROSS_ACCOUNT_ROOT
from ..model.enums import RuleGranularity, RuleMode

logger = logging.getLogger(__file__)


class CrossAccountTrustRule(CrossAccountCheckingRule):

    REASON = "{} has forbidden cross-account trust relationship with {}"
    ROOT_PATTERN = re.compile(REGEX_CROSS_ACCOUNT_ROOT)
    GRANULARITY = RuleGranularity.RESOURCE

    def invoke_old(self, cfmodel):
        not_has_account_id = re.compile(rf"^((?!{self._config.aws_account_id}).)*$")
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, IAMRole):

                self._detect_cross_account_root_principals(logical_id, resource)

                if self._config.aws_account_id:
                    for principal in resource.Properties.AssumeRolePolicyDocument.allowed_principals_with(
                        not_has_account_id
                    ):
                        if principal not in self.valid_principals and not principal.endswith(
                            ".amazonaws.com"
                        ):  # Checks if principal is an AWS service
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
                else:
                    logger.warning(
                        f"Not adding {type(self).__name__} failure in {logical_id} "
                        f"because no AWS Account ID was found in the config."
                    )

    def _detect_cross_account_root_principals(self, logical_id, resource):
        for principal in resource.Properties.AssumeRolePolicyDocument.allowed_principals_with(self.ROOT_PATTERN):
            account_id = get_account_id_from_principal(principal)
            if account_id not in self.valid_principals:
                self.add_failure(
                    type(self).__name__, self.REASON.format(logical_id, principal), resource_ids={logical_id}
                )

    def invoke(self, cfmodel):
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, IAMRole):
                for statement in resource.Properties.AssumeRolePolicyDocument._statement_as_list():
                    self._do_statement_check(logical_id, statement)
