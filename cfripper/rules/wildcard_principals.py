__all__ = ["GenericWildcardPrincipalRule", "PartialWildcardPrincipalRule", "FullWildcardPrincipalRule"]
import logging
import re
from typing import Dict, Optional

from pycfmodel.model.cf_model import CFModel
from pycfmodel.model.resources.iam_managed_policy import IAMManagedPolicy
from pycfmodel.model.resources.iam_policy import IAMPolicy
from pycfmodel.model.resources.iam_role import IAMRole
from pycfmodel.model.resources.iam_user import IAMUser
from pycfmodel.model.resources.properties.policy_document import PolicyDocument
from pycfmodel.model.resources.s3_bucket_policy import S3BucketPolicy
from pycfmodel.model.resources.sns_topic_policy import SNSTopicPolicy
from pycfmodel.model.resources.sqs_queue_policy import SQSQueuePolicy

from cfripper.config.regex import REGEX_FULL_WILDCARD_PRINCIPAL
from cfripper.model.enums import RuleGranularity, RuleRisk
from cfripper.model.result import Result
from cfripper.rules.base_rules import PrincipalCheckingRule

logger = logging.getLogger(__file__)


class GenericWildcardPrincipalRule(PrincipalCheckingRule):
    REASON_WILCARD_PRINCIPAL = "{} should not allow wildcard in principals or account-wide principals (principal: '{}')"
    GRANULARITY = RuleGranularity.RESOURCE

    IAM_PATTERN = re.compile(r"arn:aws:iam::(\d*|\*):.*")
    FULL_REGEX = re.compile(r"^((\w*:){0,1}\*|arn:aws:iam::(\d*|\*):.*)$")

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, (IAMManagedPolicy, IAMPolicy, S3BucketPolicy, SNSTopicPolicy, SQSQueuePolicy)):
                self.check_for_wildcards(result, logical_id, resource.Properties.PolicyDocument, extras)
            elif isinstance(resource, (IAMRole, IAMUser)):
                if isinstance(resource, IAMRole):
                    self.check_for_wildcards(result, logical_id, resource.Properties.AssumeRolePolicyDocument, extras)
                if resource.Properties and resource.Properties.Policies:
                    for policy in resource.Properties.Policies:
                        self.check_for_wildcards(result, logical_id, policy.PolicyDocument, extras)
        return result

    def check_for_wildcards(
        self, result: Result, logical_id: str, resource: PolicyDocument, extras: Optional[Dict] = None
    ):
        for statement in resource._statement_as_list():
            if statement.Effect == "Allow" and statement.principals_with(self.FULL_REGEX):
                for principal in statement.get_principal_list():
                    account_id_match = self.IAM_PATTERN.match(principal)
                    account_id = account_id_match.group(1) if account_id_match else None

                    # Check if account ID is allowed. `self._get_allowed_from_config()` used here
                    # to reduce number of false negatives and only allow exemptions for accounts
                    # which belong to AWS Services (such as ELB and ElastiCache).
                    if account_id in self._get_allowed_from_config():
                        continue

                    if statement.Condition and statement.Condition.dict():
                        logger.warning(
                            f"Not adding {type(self).__name__} failure in {logical_id} because there are conditions: "
                            f"{statement.Condition}"
                        )
                    else:
                        self.add_failure_to_result(
                            result,
                            self.REASON_WILCARD_PRINCIPAL.format(logical_id, principal),
                            resource_ids={logical_id},
                            context={
                                "config": self._config,
                                "extras": extras,
                                "logical_id": logical_id,
                                "resource": resource,
                                "statement": statement,
                                "principal": principal,
                                "account_id": account_id,
                            },
                        )


class PartialWildcardPrincipalRule(GenericWildcardPrincipalRule):
    """
    Checks for any wildcard or account-wide principals defined in any statements. This rule will flag
    as non-compliant any principals where `root` or `*` are included at the end of the value, for
    example, `arn:aws:iam:12345:12345*`.

    Risk:
        It might allow other AWS identities or the root access of the account to escalate privileges.

    Fix:
        Where possible, restrict the access to only the required resources.
        For example, instead of `Principal: "*"`, include a list of the roles that need access.

    Filters context:
        | Parameter   | Type               | Description                                                    |
        |:-----------:|:------------------:|:--------------------------------------------------------------:|
        |`config`     | str                | `config` variable available inside the rule                    |
        |`extras`     | str                | `extras` variable available inside the rule                    |
        |`logical_id` | str                | ID used in Cloudformation to refer the resource being analysed |
        |`resource`   | `S3BucketPolicy`   | Resource that is being addressed                               |
        |`statement`  | `Statement`        | Statement being checked found in the Resource                  |
        |`principal`  | str                | AWS Principal being checked found in the statement             |
        |`account_id` | str                | Account ID found in the principal                              |
    """

    REASON_WILCARD_PRINCIPAL = "{} should not allow wildcard in principals or account-wide principals (principal: '{}')"

    RISK_VALUE = RuleRisk.MEDIUM
    """
    Will catch:

    - Principal: arn:aws:iam:12345:12345*

    """
    FULL_REGEX = re.compile(r"^arn:aws:iam::.*:(.*\*|root)$")


class FullWildcardPrincipalRule(GenericWildcardPrincipalRule):
    """
    Checks for any wildcard principals defined in any statements.

    Risk:
        It might allow other AWS identities to escalate privileges.

    Fix:
        Where possible, restrict the access to only the required resources.
        For example, instead of `Principal: "*"`, include a list of the roles that need access.

    Filters context:
        | Parameter   | Type               | Description                                                    |
        |:-----------:|:------------------:|:--------------------------------------------------------------:|
        |`config`     | str                | `config` variable available inside the rule                    |
        |`extras`     | str                | `extras` variable available inside the rule                    |
        |`logical_id` | str                | ID used in Cloudformation to refer the resource being analysed |
        |`resource`   | `S3BucketPolicy`   | Resource that is being addressed                               |
        |`statement`  | `Statement`        | Statement being checked found in the Resource                  |
        |`principal`  | str                | AWS Principal being checked found in the statement             |
        |`account_id` | str                | Account ID found in the principal                              |
    """

    REASON_WILCARD_PRINCIPAL = "{} should not allow wildcards in principals (principal: '{}')"

    RISK_VALUE = RuleRisk.HIGH

    FULL_REGEX = REGEX_FULL_WILDCARD_PRINCIPAL
