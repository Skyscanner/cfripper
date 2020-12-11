__all__ = ["SQSQueuePolicyNotPrincipalRule", "SQSQueuePolicyPublicRule", "SQSDangerousPolicyActionsRule"]

import logging
from typing import Dict, Optional

from pycfmodel.model.resources.sqs_queue_policy import SQSQueuePolicy

from cfripper.config.regex import REGEX_HAS_STAR_OR_STAR_AFTER_COLON
from cfripper.model.enums import RuleGranularity, RuleRisk
from cfripper.model.result import Result
from cfripper.rules.base_rules import BaseDangerousPolicyActions, ResourceSpecificRule

logger = logging.getLogger(__file__)


class SQSQueuePolicyNotPrincipalRule(ResourceSpecificRule):
    """
    Checks if an SQS Queue policy has an Allow + a NotPrincipal.

    Risk:
        AWS **strongly** recommends against using `NotPrincipal` in the same policy statement as `"Effect": "Allow"`.
        Doing so grants the permissions specified in the policy statement to all principals except the one named
        in the `NotPrincipal` element. By doing this, you might grant access to anonymous (unauthenticated) users.
    """

    GRANULARITY = RuleGranularity.RESOURCE
    RESOURCE_TYPES = (SQSQueuePolicy,)
    REASON = "SQS Queue policy {} should not allow Allow and NotPrincipal at the same time"

    def resource_invoke(self, resource: SQSQueuePolicy, logical_id: str, extras: Optional[Dict] = None) -> Result:
        result = Result()
        for statement in resource.Properties.PolicyDocument._statement_as_list():
            if statement.NotPrincipal:
                self.add_failure_to_result(result, self.REASON.format(logical_id), resource_ids={logical_id})
        return result


class SQSQueuePolicyPublicRule(ResourceSpecificRule):
    """
    Checks for wildcard principals in Allow statements in an SQS Queue Policy.

    Risk:
        This is deemed a potential security risk as anyone would be able to interact with your queue.
    """

    REASON = "SQS Queue policy {} should not be public"
    RISK_VALUE = RuleRisk.HIGH
    GRANULARITY = RuleGranularity.RESOURCE
    RESOURCE_TYPES = (SQSQueuePolicy,)

    def resource_invoke(self, resource: SQSQueuePolicy, logical_id: str, extras: Optional[Dict] = None) -> Result:
        result = Result()
        if resource.Properties.PolicyDocument.allowed_principals_with(REGEX_HAS_STAR_OR_STAR_AFTER_COLON):
            for statement in resource.Properties.PolicyDocument._statement_as_list():
                if statement.Effect == "Allow" and statement.principals_with(REGEX_HAS_STAR_OR_STAR_AFTER_COLON):
                    if statement.Condition and statement.Condition.dict():
                        logger.warning(
                            f"Not adding {type(self).__name__} failure in {logical_id} "
                            f"because there are conditions: {statement.Condition}"
                        )
                    else:
                        self.add_failure_to_result(result, self.REASON.format(logical_id), resource_ids={logical_id})
        return result


class SQSDangerousPolicyActionsRule(BaseDangerousPolicyActions):
    f"""
    Checks for dangerous permissions in Action statements in an SQS Queue Policy.

    Risk:
        This is deemed a potential security risk as it'd allow various attacks to the queue.

    {BaseDangerousPolicyActions.DEFAULT_FILTERS_CONTEXT}
    """

    REASON = "SQS Queue policy {} should not not include the following dangerous actions: {}"
    RISK_VALUE = RuleRisk.MEDIUM
    RESOURCE_TYPES = (SQSQueuePolicy,)

    DANGEROUS_ACTIONS = [
        "sqs:AddPermission",
        "sqs:CreateQueue",
        "sqs:DeleteQueue",
        "sqs:RemovePermission",
        "sqs:TagQueue",
        "sqs:UnTagQueue",
    ]
