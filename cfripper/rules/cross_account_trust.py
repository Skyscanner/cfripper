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
__all__ = [
    "CrossAccountCheckingRule",
    "CrossAccountTrustRule",
    "KMSKeyCrossAccountTrustRule",
    "S3CrossAccountTrustRule",
]

import logging
import re
from typing import Set

from pycfmodel.model.cf_model import CFModel
from pycfmodel.model.resources.iam_role import IAMRole
from pycfmodel.model.resources.kms_key import KMSKey
from pycfmodel.model.resources.s3_bucket_policy import S3BucketPolicy

from cfripper.config.regex import REGEX_CROSS_ACCOUNT_ROOT
from cfripper.model.enums import RuleGranularity, RuleMode
from cfripper.model.utils import get_account_id_from_principal
from cfripper.rules.base_rules import PrincipalCheckingRule

logger = logging.getLogger(__file__)


class CrossAccountCheckingRule(PrincipalCheckingRule):
    """
    Base class not intended to be instantiated, but inherited from.
    This class provides common methods used to detect access permissions from other accounts.
    """

    GRANULARITY = RuleGranularity.RESOURCE

    @property
    def valid_principals(self) -> Set[str]:
        if self._valid_principals is None:
            self._valid_principals = self._get_whitelist_from_config()
            if self._config.aws_account_id:
                self._valid_principals.add(self._config.aws_account_id)
        return self._valid_principals

    def _do_statement_check(self, logical_id, statement):

        if statement.Effect == "Allow":
            for principal in statement.get_principal_list():
                account_id = get_account_id_from_principal(principal)
                if (
                    # checks if principal is a canonical id and is whitelisted
                    principal not in self.valid_principals
                    # if it wasn't a canonical id and contains a valid account id
                    and account_id not in self.valid_principals
                    # if principal is an AWS service
                    and not principal.endswith(".amazonaws.com")
                ):
                    if statement.Condition and statement.Condition.dict():
                        logger.warning(
                            f"Not adding {type(self).__name__} failure in {logical_id} "
                            f"because there are conditions: {statement.Condition}"
                        )
                    elif not self._config.aws_account_id:
                        logger.warning(
                            f"Not adding {type(self).__name__} failure in {logical_id} "
                            f"because no AWS Account ID was found in the config."
                        )
                    elif "GETATT" in principal or "UNDEFINED_" in principal:
                        self.add_failure(
                            type(self).__name__,
                            self.REASON.format(logical_id, principal),
                            rule_mode=RuleMode.DEBUG,
                            resource_ids={logical_id},
                        )
                    else:
                        self.add_failure(
                            type(self).__name__, self.REASON.format(logical_id, principal), resource_ids={logical_id}
                        )


class CrossAccountTrustRule(CrossAccountCheckingRule):
    """
    Checks if the trust policy of a role grants permissions to principals from other accounts.
    Do not use whole accounts as principals.

    Risk:
        It might allow other AWS identities to escalate privileges.

    Fix:
        If cross account permissions are required, the stack should be added to the whitelist for this rule.
        Otherwise, the access should be removed from the CloudFormation definition.
    """

    REASON = "{} has forbidden cross-account trust relationship with {}"
    ROOT_PATTERN = re.compile(REGEX_CROSS_ACCOUNT_ROOT)

    def invoke(self, cfmodel):
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, IAMRole):
                for statement in resource.Properties.AssumeRolePolicyDocument._statement_as_list():
                    self._do_statement_check(logical_id, statement)


class S3CrossAccountTrustRule(CrossAccountCheckingRule):
    """
    Check for cross account access in S3 bucket policies. Cross account access by default should not be allowed.

    Risk:
        It might allow other AWS identities to access/modify content of the bucket.

    Fix:
        If cross account permissions are required for S3 access, the stack should be added to the whitelist for this rule.
        Otherwise, the access should be removed from the CloudFormation definition.
    """

    REASON = "{} has forbidden cross-account policy allow with {} for an S3 bucket."

    def invoke(self, cfmodel):
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, S3BucketPolicy):
                for statement in resource.Properties.PolicyDocument._statement_as_list():
                    self._do_statement_check(logical_id, statement)


class KMSKeyCrossAccountTrustRule(CrossAccountCheckingRule):
    """
    Checks for KMS keys that allow cross-account principals to get access to the key.

    Risk:
        It might allow other AWS identities to read/modify the secrets.

    Fix:
        If cross account permissions are required for KMS access, the stack should be added to the whitelist for this rule.
        Otherwise, the access should be removed from the CloudFormation definition.
    """

    REASON = "{} has forbidden cross-account policy allow with {} for an KMS Key Policy"

    def invoke(self, cfmodel: CFModel):
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, KMSKey):
                for statement in resource.Properties.KeyPolicy._statement_as_list():
                    self._do_statement_check(logical_id, statement)
