__all__ = ["PrivilegeEscalationRule"]

from typing import Dict, Optional

from pycfmodel.model.cf_model import CFModel
from pycfmodel.model.resources.iam_policy import IAMPolicy

from cfripper.model.enums import RuleGranularity
from cfripper.model.result import Result
from cfripper.rules.base_rules import Rule


class PrivilegeEscalationRule(Rule):
    """
    Checks for any dangerous IAM actions that could allow privilege escalation and potentially
    represent a large security risk.
    See [current blacklisted IAM actions](https://github.com/Skyscanner/cfripper/blob/master/cfripper/rules/privilege_escalation.py#L29).

    Fix:
        Unless strictly necessary, do not use actions in the IAM action blacklist. CloudFormation files that do require these
        actions should be added to the whitelist.
    """

    GRANULARITY = RuleGranularity.RESOURCE
    REASON = "{} has blacklisted IAM action {}"
    IAM_BLACKLIST = set(
        action.lower()
        for action in [
            "iam:CreateAccessKey",
            "iam:CreateLoginProfile",
            "iam:UpdateLoginProfile",
            "iam:AttachUserPolicy",
            "iam:AttachGroupPolicy",
            "iam:AttachRolePolicy",
            "iam:PutUserPolicy",
            "iam:PutGroupPolicy",
            "iam:PutRolePolicy",
            "iam:CreatePolicy",
            "iam:AddUserToGroup",
            "iam:UpdateAssumeRolePolicy",
            "iam:CreatePolicyVersion",
            "iam:SetDefaultPolicyVersion",
        ]
    )

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, IAMPolicy):
                policy_actions = set(action.lower() for action in resource.Properties.PolicyDocument.get_iam_actions())
                for violation in policy_actions.intersection(self.IAM_BLACKLIST):
                    self.add_failure_to_result(
                        result, self.REASON.format(logical_id, violation), resource_ids={logical_id}
                    )
        return result
