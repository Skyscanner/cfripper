__all__ = [
    "GenericWildcardPrincipalRule",
    "PartialWildcardPrincipalRule",
    "FullWildcardPrincipalRule",
    "GenericResourceWildcardPrincipalRule",
    "GenericResourcePartialWildcardPrincipalRule",
    "GenericResourceFullWildcardPrincipalRule",
]
import logging
import re
from typing import Dict, Optional

from pycfmodel.model.cf_model import CFModel
from pycfmodel.model.resources.iam_managed_policy import IAMManagedPolicy
from pycfmodel.model.resources.iam_policy import IAMPolicy
from pycfmodel.model.resources.iam_role import IAMRole
from pycfmodel.model.resources.iam_user import IAMUser
from pycfmodel.model.resources.kms_key import KMSKey
from pycfmodel.model.resources.properties.policy_document import PolicyDocument
from pycfmodel.model.resources.s3_bucket_policy import S3BucketPolicy
from pycfmodel.model.resources.sns_topic_policy import SNSTopicPolicy
from pycfmodel.model.resources.sqs_queue_policy import SQSQueuePolicy

from cfripper.config.regex import REGEX_FULL_WILDCARD_PRINCIPAL, REGEX_PARTIAL_WILDCARD_PRINCIPAL
from cfripper.model.enums import RuleGranularity, RuleRisk
from cfripper.model.result import Result
from cfripper.rules.base_rules import PrincipalCheckingRule

logger = logging.getLogger(__file__)


class GenericWildcardPrincipalRule(PrincipalCheckingRule):
    """
    Checks for any wildcard principal defined in any statement.
    Only for: IAMManagedPolicy, IAMPolicy, S3BucketPolicy, SNSTopicPolicy and SQSQueuePolicy
    To be inherited into more precise rules.
    Ignores KMS Keys, since they have `KMSKeyWildcardPrincipalRule`.
    For IAM Roles, it also checks `AssumeRolePolicyDocument`.

    Risk:
        It might allow other AWS identities to escalate privileges.

    Fix:
        Where possible, restrict the access to only the required resources.
        For example, instead of `Principal: "*"`, include a list of the roles that need access.

    Filters context:
        | Parameter   | Type               | Description                                                    |
        |:-----------:|:------------------:|:--------------------------------------------------------------:|
        |`config`     | `str`              | `config` variable available inside the rule                    |
        |`extras`     | `str`              | `extras` variable available inside the rule                    |
        |`logical_id` | `str`              | ID used in CloudFormation to refer the resource being analysed |
        |`resource`   | `S3BucketPolicy`   | Resource that is being addressed                               |
        |`statement`  | `Statement`        | Statement being checked found in the Resource                  |
        |`principal`  | `str`              | AWS Principal being checked found in the statement             |
        |`account_id` | `str`              | Account ID found in the principal                              |
    """

    REASON_WILDCARD_PRINCIPAL = "{} should not allow wildcards in principals (principal: '{}')"
    GRANULARITY = RuleGranularity.RESOURCE

    AWS_ACCOUNT_ID_PATTERN = re.compile(r"^(\d{12})$")
    IAM_PATTERN = re.compile(r"arn:aws:iam::(\d*|\*):.*")
    FULL_REGEX = REGEX_FULL_WILDCARD_PRINCIPAL

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, (IAMManagedPolicy, IAMPolicy, S3BucketPolicy, SNSTopicPolicy, SQSQueuePolicy)):
                self.check_for_wildcards(
                    result=result,
                    logical_id=logical_id,
                    resource=resource.Properties.PolicyDocument,
                    resource_type=resource.Type,
                    extras=extras,
                )
            elif isinstance(resource, (IAMRole, IAMUser)):
                if isinstance(resource, IAMRole):
                    self.check_for_wildcards(
                        result=result,
                        logical_id=logical_id,
                        resource=resource.Properties.AssumeRolePolicyDocument,
                        resource_type=resource.Type,
                        extras=extras,
                    )
                if resource.Properties and resource.Properties.Policies:
                    for policy in resource.Properties.Policies:
                        self.check_for_wildcards(
                            result=result,
                            logical_id=logical_id,
                            resource=policy.PolicyDocument,
                            resource_type=resource.Type,
                            extras=extras,
                        )

        return result

    def check_for_wildcards(
        self,
        result: Result,
        logical_id: str,
        resource: PolicyDocument,
        resource_type: str,
        extras: Optional[Dict] = None,
    ):
        for statement in resource.statement_as_list():
            if statement.Effect == "Allow" and statement.principals_with(self.FULL_REGEX):
                for principal in statement.get_principal_list():
                    account_id_match = self.IAM_PATTERN.match(principal) or self.AWS_ACCOUNT_ID_PATTERN.match(principal)
                    account_id = account_id_match.group(1) if account_id_match else None

                    # Check if account ID is allowed. `self._get_allowed_from_config()` used here
                    # to reduce number of false negatives and only allow exemptions for accounts
                    # which belong to AWS Services (such as ELB and ElastiCache).
                    if account_id in self._get_allowed_from_config():
                        continue
                    if statement.Condition and statement.Condition.dict():
                        # Ignoring condition checks since they will get reviewed in other rules and future improvements
                        continue
                    else:
                        self.add_failure_to_result(
                            result,
                            self.REASON_WILDCARD_PRINCIPAL.format(logical_id, principal),
                            resource_ids={logical_id},
                            resource_types={resource_type},
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
        |`config`     | `str`              | `config` variable available inside the rule                    |
        |`extras`     | `str`              | `extras` variable available inside the rule                    |
        |`logical_id` | `str`              | ID used in CloudFormation to refer the resource being analysed |
        |`resource`   | `S3BucketPolicy`   | Resource that is being addressed                               |
        |`statement`  | `Statement`        | Statement being checked found in the Resource                  |
        |`principal`  | `str`              | AWS Principal being checked found in the statement             |
        |`account_id` | `str`              | Account ID found in the principal                              |
    """

    REASON_WILDCARD_PRINCIPAL = (
        "{} should not allow wildcard in principals or account-wide principals (principal: '{}')"
    )
    RISK_VALUE = RuleRisk.MEDIUM
    FULL_REGEX = REGEX_PARTIAL_WILDCARD_PRINCIPAL


class FullWildcardPrincipalRule(GenericWildcardPrincipalRule):
    """
    Checks for any wildcard principal defined in any statement.

    Risk:
        It might allow other AWS identities to escalate privileges.

    Fix:
        Where possible, restrict the access to only the required resources.
        For example, instead of `Principal: "*"`, include a list of the roles that need access.

    Filters context:
        | Parameter   | Type               | Description                                                    |
        |:-----------:|:------------------:|:--------------------------------------------------------------:|
        |`config`     | `str`              | `config` variable available inside the rule                    |
        |`extras`     | `str`              | `extras` variable available inside the rule                    |
        |`logical_id` | `str`              | ID used in CloudFormation to refer the resource being analysed |
        |`resource`   | `S3BucketPolicy`   | Resource that is being addressed                               |
        |`statement`  | `Statement`        | Statement being checked found in the Resource                  |
        |`principal`  | `str`              | AWS Principal being checked found in the statement             |
        |`account_id` | `str`              | Account ID found in the principal                              |
    """

    RISK_VALUE = RuleRisk.HIGH


class GenericResourceWildcardPrincipalRule(GenericWildcardPrincipalRule):
    """
    Checks for any wildcard principal defined in any statement for any type of resource.
    To be inherited into more precise rules.
    Ignores KMS Keys, since they have `KMSKeyWildcardPrincipalRule`.
    For IAM Roles, it also checks `AssumeRolePolicyDocument`.

    Risk:
        It might allow other AWS identities to escalate privileges.

    Fix:
        Where possible, restrict the access to only the required resources.
        For example, instead of `Principal: "*"`, include a list of the roles that need access.

    Filters context:
        | Parameter   | Type               | Description                                                    |
        |:-----------:|:------------------:|:--------------------------------------------------------------:|
        |`config`     | `str`              | `config` variable available inside the rule                    |
        |`extras`     | `str`              | `extras` variable available inside the rule                    |
        |`logical_id` | `str`              | ID used in CloudFormation to refer the resource being analysed |
        |`resource`   | `S3BucketPolicy`   | Resource that is being addressed                               |
        |`statement`  | `Statement`        | Statement being checked found in the Resource                  |
        |`principal`  | `str`              | AWS Principal being checked found in the statement             |
        |`account_id` | `str`              | Account ID found in the principal                              |
    """

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, KMSKey):
                # Ignoring KMSKey because there's already a rule for it `KMSKeyWildcardPrincipalRule`
                continue
            if isinstance(resource, IAMRole):
                # Checking the `AssumeRolePolicyDocument` for IAM Roles
                self.check_for_wildcards(
                    result=result,
                    logical_id=logical_id,
                    resource=resource.Properties.AssumeRolePolicyDocument,
                    resource_type=resource.Type,
                    extras=extras,
                )
            for policy in resource.policy_documents:
                self.check_for_wildcards(
                    result=result,
                    logical_id=logical_id,
                    resource=policy.policy_document,
                    resource_type=resource.Type,
                    extras=extras,
                )

        return result


class GenericResourcePartialWildcardPrincipalRule(GenericResourceWildcardPrincipalRule):
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
        |`config`     | `str`              | `config` variable available inside the rule                    |
        |`extras`     | `str`              | `extras` variable available inside the rule                    |
        |`logical_id` | `str`              | ID used in CloudFormation to refer the resource being analysed |
        |`resource`   | `S3BucketPolicy`   | Resource that is being addressed                               |
        |`statement`  | `Statement`        | Statement being checked found in the Resource                  |
        |`principal`  | `str`              | AWS Principal being checked found in the statement             |
        |`account_id` | `str`              | Account ID found in the principal                              |
    """

    REASON_WILDCARD_PRINCIPAL = (
        "{} should not allow wildcard in principals or account-wide principals (principal: '{}')"
    )
    RISK_VALUE = RuleRisk.MEDIUM
    FULL_REGEX = REGEX_PARTIAL_WILDCARD_PRINCIPAL


class GenericResourceFullWildcardPrincipalRule(GenericResourceWildcardPrincipalRule):
    """
    Checks for any wildcard principal defined in any statement.

    Risk:
        It might allow other AWS identities to escalate privileges.

    Fix:
        Where possible, restrict the access to only the required resources.
        For example, instead of `Principal: "*"`, include a list of the roles that need access.

    Filters context:
        | Parameter   | Type               | Description                                                    |
        |:-----------:|:------------------:|:--------------------------------------------------------------:|
        |`config`     | `str`              | `config` variable available inside the rule                    |
        |`extras`     | `str`              | `extras` variable available inside the rule                    |
        |`logical_id` | `str`              | ID used in CloudFormation to refer the resource being analysed |
        |`resource`   | `S3BucketPolicy`   | Resource that is being addressed                               |
        |`statement`  | `Statement`        | Statement being checked found in the Resource                  |
        |`principal`  | `str`              | AWS Principal being checked found in the statement             |
        |`account_id` | `str`              | Account ID found in the principal                              |
    """

    RISK_VALUE = RuleRisk.HIGH
