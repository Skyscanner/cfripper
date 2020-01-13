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
__all__ = ["SQSQueuePolicyNotPrincipalRule", "SQSQueuePolicyPublicRule", "SQSQueuePolicyWildcardActionRule"]

import logging

from pycfmodel.model.resources.sqs_queue_policy import SQSQueuePolicy

from cfripper.config.regex import REGEX_HAS_STAR_OR_STAR_AFTER_COLON
from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.rule import Rule

logger = logging.getLogger(__file__)


class SQSQueuePolicyNotPrincipalRule(Rule):
    """
    Checks if an SQS Queue policy has an Allow + a NotPrincipal (exclusive principal).
    """

    GRANULARITY = RuleGranularity.RESOURCE
    REASON = "SQS Queue {} policy should not allow Allow and NotPrincipal at the same time"
    RULE_MODE = RuleMode.MONITOR

    def invoke(self, cfmodel):
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, SQSQueuePolicy):
                for statement in resource.Properties.PolicyDocument._statement_as_list():
                    if statement.NotPrincipal:
                        self.add_failure(type(self).__name__, self.REASON.format(logical_id), resource_ids={logical_id})


class SQSQueuePolicyPublicRule(Rule):
    """
    Checks for wildcard principals in Allow statements in an SQS Queue Policy.

    Risk:
        This is deemed a potential security risk as anyone would be able to interact with your queue.
    """

    REASON = "SQS Queue policy {} should not be public"
    RISK_VALUE = RuleRisk.HIGH

    def invoke(self, cfmodel):
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, SQSQueuePolicy) and resource.Properties.PolicyDocument.allowed_principals_with(
                REGEX_HAS_STAR_OR_STAR_AFTER_COLON
            ):
                for statement in resource.Properties.PolicyDocument._statement_as_list():
                    if statement.Effect == "Allow" and statement.principals_with(REGEX_HAS_STAR_OR_STAR_AFTER_COLON):
                        if statement.Condition and statement.Condition.dict():
                            logger.warning(
                                f"Not adding {type(self).__name__} failure in {logical_id} "
                                f"because there are conditions: {statement.Condition}"
                            )
                        else:
                            self.add_failure(
                                type(self).__name__, self.REASON.format(logical_id), resource_ids={logical_id}
                            )


class SQSQueuePolicyWildcardActionRule(Rule):
    """
    Checks if an SQS Queue Policy contains a `*` for any action in the policy document.

    Risk:
        Wildcards are always dangerous to use if not all of the actions of a feature (like SQS) are known.
        For example, `sqs:Delete*` might be acceptable if a service needs to delete messages from a queue.
        However, this will allow the role to perform `sqs:DeleteQueue`, which can delete non-empty queues.

    Fix:
        Policies with wildcards contained in the `Action` statements should be reviewed. Writing out the actions
        verbosely is sometimes clearer and safer. Stacks can be whitelisted otherwise.
    """

    REASON = "SQS Queue policy {} should not allow * action"

    def invoke(self, cfmodel):
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, SQSQueuePolicy) and resource.Properties.PolicyDocument.allowed_actions_with(
                REGEX_HAS_STAR_OR_STAR_AFTER_COLON
            ):
                self.add_failure(type(self).__name__, self.REASON.format(logical_id), resource_ids={logical_id})
