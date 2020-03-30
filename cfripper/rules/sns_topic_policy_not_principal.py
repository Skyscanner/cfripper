__all__ = ["SNSTopicPolicyNotPrincipalRule"]

from typing import Dict, Optional

from pycfmodel.model.cf_model import CFModel
from pycfmodel.model.resources.sns_topic_policy import SNSTopicPolicy

from cfripper.model.enums import RuleGranularity, RuleMode
from cfripper.model.result import Result
from cfripper.rules.base_rules import Rule


class SNSTopicPolicyNotPrincipalRule(Rule):
    """
    Checks if an SNS topic policy has an Allow + a NotPrincipal (exclusive principal).
    """

    GRANULARITY = RuleGranularity.RESOURCE
    REASON = "SNS Topic {} policy should not allow Allow and NotPrincipal at the same time"
    RULE_MODE = RuleMode.MONITOR

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, SNSTopicPolicy):
                for statement in resource.Properties.PolicyDocument._statement_as_list():
                    if statement.NotPrincipal:
                        self.add_failure_to_result(result, self.REASON.format(logical_id), resource_ids={logical_id})
        return result
