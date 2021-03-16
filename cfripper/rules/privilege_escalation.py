__all__ = ["PrivilegeEscalationRule"]

from pycfmodel.model.resources.resource import Resource
from pycfmodel.model.resources.s3_bucket_policy import S3BucketPolicy

from cfripper.model.enums import RuleGranularity
from cfripper.rules.base_rules import BaseDangerousPolicyActions


class PrivilegeEscalationRule(BaseDangerousPolicyActions):
    f"""
    Checks for any dangerous IAM actions that could allow privilege escalation and potentially
    represent a large security risk.
    See [current blacklisted IAM actions]\
(https://github.com/Skyscanner/cfripper/blob/master/cfripper/rules/privilege_escalation.py#L25).

    Fix:
        Unless strictly necessary, do not use actions in the IAM action blacklist. CloudFormation files that do require
        these actions should be added to the allowlist.

    {BaseDangerousPolicyActions.DEFAULT_FILTERS_CONTEXT}
    """

    GRANULARITY = RuleGranularity.ACTION
    REASON = "{} has blacklisted IAM actions: {}"
    EXCLUDED_RESOURCE_TYPES = (S3BucketPolicy,)
    RESOURCE_TYPES = (Resource,)
    DANGEROUS_ACTIONS = [
        "iam:AddUserToGroup",
        "iam:AttachGroupPolicy",
        "iam:AttachRolePolicy",
        "iam:AttachUserPolicy",
        "iam:CreateAccessKey",
        "iam:CreateLoginProfile",
        "iam:CreatePolicy",
        "iam:CreatePolicyVersion",
        "iam:PutGroupPolicy",
        "iam:PutRolePolicy",
        "iam:PutUserPolicy",
        "iam:SetDefaultPolicyVersion",
        "iam:UpdateAssumeRolePolicy",
        "iam:UpdateLoginProfile",
    ]
