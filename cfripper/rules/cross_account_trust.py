__all__ = [
    "CrossAccountCheckingRule",
    "CrossAccountTrustRule",
    "ElasticsearchDomainCrossAccountTrustRule",
    "GenericCrossAccountTrustRule",
    "KMSKeyCrossAccountTrustRule",
    "OpenSearchDomainCrossAccountTrustRule",
    "S3CrossAccountTrustRule",
]

import logging
from abc import ABC
from typing import Dict, Optional, Set

from pycfmodel.model.cf_model import CFModel
from pycfmodel.model.resources.es_domain import ESDomain
from pycfmodel.model.resources.iam_role import IAMRole
from pycfmodel.model.resources.kms_key import KMSKey
from pycfmodel.model.resources.opensearch_domain import OpenSearchDomain
from pycfmodel.model.resources.properties.statement import Statement
from pycfmodel.model.resources.resource import Resource
from pycfmodel.model.resources.s3_bucket_policy import S3BucketPolicy

from cfripper.model.enums import RuleGranularity, RuleMode
from cfripper.model.result import Result
from cfripper.model.utils import get_account_id_from_principal
from cfripper.rules.base_rules import PrincipalCheckingRule

logger = logging.getLogger(__file__)


class CrossAccountCheckingRule(PrincipalCheckingRule, ABC):
    """
    Base class not intended to be instantiated, but inherited from.
    This class provides common methods used to detect access permissions from other accounts.
    """

    GRANULARITY = RuleGranularity.RESOURCE
    RESOURCE_TYPE: Resource
    PROPERTY_WITH_POLICYDOCUMENT: str

    @property
    def valid_principals(self) -> Set[str]:
        if self._valid_principals is None:
            self._valid_principals = self._get_allowed_from_config()
            if self._config.aws_account_id:
                self._valid_principals.add(self._config.aws_account_id)
        return self._valid_principals

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, self.RESOURCE_TYPE):
                properties = resource.Properties
                policy_document = getattr(properties, self.PROPERTY_WITH_POLICYDOCUMENT)
                if policy_document:
                    for statement in policy_document.statement_as_list():
                        filters_available_context = {
                            "config": self._config,
                            "extras": extras,
                            "logical_id": logical_id,
                            "resource": resource,
                            "statement": statement,
                        }
                        self._do_statement_check(result, logical_id, statement, filters_available_context, resource)
        return result

    def _do_statement_check(
        self, result: Result, logical_id: str, statement: Statement, filters_available_context: Dict, resource: Resource
    ):
        if statement.Effect == "Allow":
            for principal in statement.get_principal_list():
                account_id = get_account_id_from_principal(principal)
                filters_available_context["principal"] = principal
                filters_available_context["account_id"] = account_id
                if (
                    # checks if principal is a canonical id and is allowed
                    principal not in self.valid_principals
                    # if it wasn't a canonical id and contains a valid account id
                    and account_id not in self.valid_principals
                    # if principal is an AWS service
                    and not principal.endswith(".amazonaws.com")
                ):
                    if statement.Condition and statement.Condition.dict():
                        # Ignoring condition checks since they will get reviewed in other rules and future improvements
                        pass
                    elif not self._config.aws_account_id:
                        logger.warning(
                            f"Not adding {type(self).__name__} failure in {logical_id} "
                            f"because no AWS Account ID was found in the config."
                        )
                    elif principal.startswith("GETATT") or principal.startswith("UNDEFINED_"):
                        self.add_failure_to_result(
                            result,
                            self.REASON.format(logical_id, principal),
                            rule_mode=RuleMode.DEBUG,
                            resource_ids={logical_id},
                            context=filters_available_context,
                            resource_types={resource.Type},
                        )
                    else:
                        self.add_failure_to_result(
                            result,
                            self.REASON.format(logical_id, principal),
                            resource_ids={logical_id},
                            context=filters_available_context,
                            resource_types={resource.Type},
                        )


class GenericCrossAccountTrustRule(CrossAccountCheckingRule):
    """
    Checks if the trust policy of every resource grants permissions to principals from other accounts.
    Do not use whole accounts as principals.
    It doesn't check if policies allow permissions to assume roles in other accounts.

    Risk:
        It might allow other AWS identities to escalate privileges.

    Fix:
        If cross account permissions are required, the stack should be added to the allowlist for this rule.
        Otherwise, the access should be removed from the CloudFormation definition.

    Filters context:
        | Parameter   | Type        | Description                                                    |
        |:-----------:|:-----------:|:--------------------------------------------------------------:|
        |`config`     | `str`       | `config` variable available inside the rule                    |
        |`extras`     | `str`       | `extras` variable available inside the rule                    |
        |`logical_id` | `str`       | ID used in CloudFormation to refer the resource being analysed |
        |`resource`   | `Generic`   | Resource that is being addressed                               |
        |`statement`  | `Statement` | Statement being checked found in the Resource                  |
        |`principal`  | `str`       | AWS Principal being checked found in the statement             |
        |`account_id` | `str`       | Account ID found in the principal                              |
    """

    REASON = "{} has forbidden cross-account with {}"

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, IAMRole):
                policy_documents = resource.assume_role_as_optionally_named_policy_document_list
            else:
                policy_documents = resource.policy_documents
            if policy_documents:
                for document in policy_documents:
                    for statement in document.policy_document.statement_as_list():
                        filters_available_context = {
                            "config": self._config,
                            "extras": extras,
                            "logical_id": logical_id,
                            "resource": resource,
                            "statement": statement,
                        }
                        self._do_statement_check(result, logical_id, statement, filters_available_context, resource)

        return result


class CrossAccountTrustRule(CrossAccountCheckingRule):
    """
    To be replaced by GenericCrossAccountTrustRule.

    Checks if the trust policy of a role grants permissions to principals from other accounts.
    Do not use whole accounts as principals.

    Risk:
        It might allow other AWS identities to escalate privileges.

    Fix:
        If cross account permissions are required, the stack should be added to the allowlist for this rule.
        Otherwise, the access should be removed from the CloudFormation definition.

    Filters context:
        | Parameter   | Type        | Description                                                    |
        |:-----------:|:-----------:|:--------------------------------------------------------------:|
        |`config`     | `str`       | `config` variable available inside the rule                    |
        |`extras`     | `str`       | `extras` variable available inside the rule                    |
        |`logical_id` | `str`       | ID used in CloudFormation to refer the resource being analysed |
        |`resource`   | `IAMRole`   | Resource that is being addressed                               |
        |`statement`  | `Statement` | Statement being checked found in the Resource                  |
        |`principal`  | `str`       | AWS Principal being checked found in the statement             |
        |`account_id` | `str`       | Account ID found in the principal                              |
    """

    REASON = "{} has forbidden cross-account trust relationship with {}"
    RESOURCE_TYPE = IAMRole
    PROPERTY_WITH_POLICYDOCUMENT = "AssumeRolePolicyDocument"


class S3CrossAccountTrustRule(CrossAccountCheckingRule):
    """
    To be replaced by GenericCrossAccountTrustRule.

    Check for cross account access in S3 bucket policies. Cross account access by default should not be allowed.

    Risk:
        It might allow other AWS identities to access/modify content of the bucket.

    Fix:
        If cross account permissions are required for S3 access, the stack should be added to the allowlist for this rule.
        Otherwise, the access should be removed from the CloudFormation definition.

    Filters context:
        | Parameter   | Type             | Description                                                    |
        |:-----------:|:----------------:|:--------------------------------------------------------------:|
        |`config`     | `str`            | `config` variable available inside the rule                    |
        |`extras`     | `str`            | `extras` variable available inside the rule                    |
        |`logical_id` | `str`            | ID used in CloudFormation to refer the resource being analysed |
        |`resource`   | `S3BucketPolicy` | Resource that is being addressed                               |
        |`statement`  | `Statement`      | Statement being checked found in the Resource                  |
        |`principal`  | `str`            | AWS Principal being checked found in the statement             |
        |`account_id` | `str`            | Account ID found in the principal                              |
    """

    REASON = "{} has forbidden cross-account policy allow with {} for an S3 bucket."
    RESOURCE_TYPE = S3BucketPolicy
    PROPERTY_WITH_POLICYDOCUMENT = "PolicyDocument"


class KMSKeyCrossAccountTrustRule(CrossAccountCheckingRule):
    """
    To be replaced by GenericCrossAccountTrustRule.

    Checks for KMS keys that allow cross-account principals to get access to the key.

    Risk:
        It might allow other AWS identities to read/modify the secrets.

    Fix:
        If cross account permissions are required for KMS access, the stack should be added to the allowlist for this rule.
        Otherwise, the access should be removed from the CloudFormation definition.

    Filters context:
        | Parameter   | Type        | Description                                                    |
        |:-----------:|:-----------:|:--------------------------------------------------------------:|
        |`config`     | `str`       | `config` variable available inside the rule                    |
        |`extras`     | `str`       | `extras` variable available inside the rule                    |
        |`logical_id` | `str`       | ID used in CloudFormation to refer the resource being analysed |
        |`resource`   | `KMSKey`    | Resource that is being addressed                               |
        |`statement`  | `Statement` | Statement being checked found in the Resource                  |
        |`principal`  | `str`       | AWS Principal being checked found in the statement             |
        |`account_id` | `str`       | Account ID found in the principal                              |
    """

    REASON = "{} has forbidden cross-account policy allow with {} for an KMS Key Policy"
    RESOURCE_TYPE = KMSKey
    PROPERTY_WITH_POLICYDOCUMENT = "KeyPolicy"


class ElasticsearchDomainCrossAccountTrustRule(CrossAccountCheckingRule):
    """
    To be replaced by GenericCrossAccountTrustRule.

    Checks for Elasticsearch domains that allow cross-account principals to get access.

    Risk:
        It might allow other AWS identities to read/modify data.

    Fix:
        If cross account permissions are required for ES domains, the stack should be added to the allowlist for this rule.
        Otherwise, the access should be removed from the CloudFormation definition.

    Filters context:
        | Parameter   | Type        | Description                                                    |
        |:-----------:|:-----------:|:--------------------------------------------------------------:|
        |`config`     | `str`       | `config` variable available inside the rule                    |
        |`extras`     | `str`       | `extras` variable available inside the rule                    |
        |`logical_id` | `str`       | ID used in CloudFormation to refer the resource being analysed |
        |`resource`   | `ESDomain`  | Resource that is being addressed                               |
        |`statement`  | `Statement` | Statement being checked found in the Resource                  |
        |`principal`  | `str`       | AWS Principal being checked found in the statement             |
        |`account_id` | `str`       | Account ID found in the principal                              |
    """

    REASON = "{} has forbidden cross-account policy allow with {} for an ES domain policy."
    RESOURCE_TYPE = ESDomain
    PROPERTY_WITH_POLICYDOCUMENT = "AccessPolicies"


class OpenSearchDomainCrossAccountTrustRule(CrossAccountCheckingRule):
    """
    To be replaced by GenericCrossAccountTrustRule.

    Checks for OpenSearch domains that allow cross-account principals to get access.

    Risk:
        It might allow other AWS identities to read/modify data.

    Fix:
        If cross account permissions are required for OpenSearch domains, the stack should be added to the allowlist for this rule.
        Otherwise, the access should be removed from the CloudFormation definition.

    Filters context:
        | Parameter   | Type               | Description                                                    |
        |:-----------:|:------------------:|:--------------------------------------------------------------:|
        |`config`     | `str`              | `config` variable available inside the rule                    |
        |`extras`     | `str`              | `extras` variable available inside the rule                    |
        |`logical_id` | `str`              | ID used in CloudFormation to refer the resource being analysed |
        |`resource`   | `OpenSearchDomain` | Resource that is being addressed                               |
        |`statement`  | `Statement`        | Statement being checked found in the Resource                  |
        |`principal`  | `str`              | AWS Principal being checked found in the statement             |
        |`account_id` | `str`              | Account ID found in the principal                              |
    """

    REASON = "{} has forbidden cross-account policy allow with {} for an OpenSearch domain policy."
    RESOURCE_TYPE = OpenSearchDomain
    PROPERTY_WITH_POLICYDOCUMENT = "AccessPolicies"
