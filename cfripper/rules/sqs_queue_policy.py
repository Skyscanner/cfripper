__all__ = ["SQSQueuePolicyNotPrincipalRule", "SQSQueuePolicyPublicRule"]

import logging
from typing import Dict, Optional

from pycfmodel.model.cf_model import CFModel
from pycfmodel.model.resources.sqs_queue_policy import SQSQueuePolicy

from cfripper.config.regex import REGEX_HAS_STAR_OR_STAR_AFTER_COLON
from cfripper.model.enums import RuleGranularity, RuleRisk
from cfripper.model.result import Result
from cfripper.rules.base_rules import Rule

logger = logging.getLogger(__file__)


class SQSQueuePolicyNotPrincipalRule(Rule):
    """
    Checks if an SQS Queue policy has an Allow + a NotPrincipal.

    Risk:
        AWS **strongly** recommends against using `NotPrincipal` in the same policy statement as `"Effect": "Allow"`.
        Doing so grants the permissions specified in the policy statement to all principals except the one named
        in the `NotPrincipal` element. By doing this, you might grant access to anonymous (unauthenticated) users.
    """

    GRANULARITY = RuleGranularity.RESOURCE
    REASON = "SQS Queue {} policy should not allow Allow and NotPrincipal at the same time"

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, SQSQueuePolicy):
                for statement in resource.Properties.PolicyDocument._statement_as_list():
                    if statement.NotPrincipal:
                        self.add_failure_to_result(result, self.REASON.format(logical_id), resource_ids={logical_id})
        return result


class SQSQueuePolicyPublicRule(Rule):
    """
    Checks for wildcard principals in Allow statements in an SQS Queue Policy.

    Risk:
        This is deemed a potential security risk as anyone would be able to interact with your queue.
    """

    REASON = "SQS Queue policy {} should not be public"
    RISK_VALUE = RuleRisk.HIGH

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()
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
                            self.add_failure_to_result(
                                result, self.REASON.format(logical_id), resource_ids={logical_id}
                            )
        return result
