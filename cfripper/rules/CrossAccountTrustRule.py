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

    def invoke(self, cfmodel):
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, IAMRole):
                for statement in resource.Properties.AssumeRolePolicyDocument._statement_as_list():
                    self._do_statement_check(logical_id, statement)
