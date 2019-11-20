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

from pycfmodel.model.resources.sqs_queue_policy import SQSQueuePolicy

from cfripper.model.enums import RuleRisk

from ..model.enums import RuleMode
from ..model.rule import Rule

logger = logging.getLogger(__file__)


class SQSQueuePolicyNotPrincipalRule(Rule):
    REASON = "SQS Queue {} policy should not allow Allow and NotPrincipal at the same time"
    RULE_MODE = RuleMode.MONITOR

    def invoke(self, cfmodel):
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, SQSQueuePolicy):
                for statement in resource.Properties.PolicyDocument._statement_as_list():
                    if statement.NotPrincipal:
                        self.add_failure(type(self).__name__, self.REASON.format(logical_id))


class SQSQueuePolicyPublicRule(Rule):

    REASON = "SQS Queue policy {} should not be public"
    RISK_VALUE = RuleRisk.HIGH
    REGEX_HAS_STAR_AFTER_COLON = re.compile(r"^(\w*:){0,1}\*$")

    def invoke(self, cfmodel):
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, SQSQueuePolicy) and resource.Properties.PolicyDocument.allowed_principals_with(
                self.REGEX_HAS_STAR_AFTER_COLON
            ):
                for statement in resource.Properties.PolicyDocument._statement_as_list():
                    if statement.Effect == "Allow" and statement.principals_with(self.REGEX_HAS_STAR_AFTER_COLON):
                        if statement.Condition and statement.Condition.dict():
                            logger.warning(
                                f"Not adding {type(self).__name__} failure in {logical_id} because there are conditions: {statement.Condition}"
                            )
                        else:
                            self.add_failure(type(self).__name__, self.REASON.format(logical_id))


class SQSQueuePolicyWildcardActionRule(Rule):

    REASON = "SQS Queue policy {} should not allow * action"

    def invoke(self, cfmodel):
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, SQSQueuePolicy) and resource.Properties.PolicyDocument.allowed_actions_with(
                re.compile(r"^(\w*:){0,1}\*$")
            ):
                self.add_failure(type(self).__name__, self.REASON.format(logical_id))
