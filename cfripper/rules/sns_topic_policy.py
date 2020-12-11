__all__ = ["SNSTopicPolicyNotPrincipalRule", "SNSTopicDangerousPolicyActionsRule"]

from typing import Dict, Optional

from pycfmodel.model.resources.sns_topic_policy import SNSTopicPolicy

from cfripper.model.enums import RuleGranularity, RuleRisk
from cfripper.model.result import Result
from cfripper.rules.base_rules import BaseDangerousPolicyActions, ResourceSpecificRule


class SNSTopicPolicyNotPrincipalRule(ResourceSpecificRule):
    """
    Checks if an SNS topic policy has an Allow + a NotPrincipal.

    Risk:
        AWS **strongly** recommends against using `NotPrincipal` in the same policy statement as `"Effect": "Allow"`.
        Doing so grants the permissions specified in the policy statement to all principals except the one named
        in the `NotPrincipal` element. By doing this, you might grant access to anonymous (unauthenticated) users.
    """

    GRANULARITY = RuleGranularity.RESOURCE
    REASON = "SNS Topic policy {} should not allow Allow and NotPrincipal at the same time"
    RESOURCE_TYPES = (SNSTopicPolicy,)

    def resource_invoke(self, resource: SNSTopicPolicy, logical_id: str, extras: Optional[Dict] = None) -> Result:
        result = Result()
        for statement in resource.Properties.PolicyDocument._statement_as_list():
            if statement.NotPrincipal:
                self.add_failure_to_result(result, self.REASON.format(logical_id), resource_ids={logical_id})
        return result


class SNSTopicDangerousPolicyActionsRule(BaseDangerousPolicyActions):
    f"""
    Checks for dangerous permissions in Action statements in an SNS Topic Policy.

    Risk:
        This is deemed a potential security risk as it could allow privilege escalation.

    {BaseDangerousPolicyActions.DEFAULT_FILTERS_CONTEXT}
    """

    REASON = "SNS Topic policy {} should not not include the following dangerous actions: {}"
    RISK_VALUE = RuleRisk.MEDIUM
    RESOURCE_TYPES = (SNSTopicPolicy,)

    DANGEROUS_ACTIONS = [
        "sns:AddPermission",
        "sns:RemovePermission",
        "sns:TagResource",
        "sns:UntagResource",
    ]
