"""
Copyright 2018-2020 Skyscanner Ltd

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
"""
from cfripper.rules.base_rules import PrincipalCheckingRule
from cfripper.rules.cloudformation_authentication import CloudFormationAuthenticationRule
from cfripper.rules.cross_account_trust import (
    CrossAccountCheckingRule,
    CrossAccountTrustRule,
    KMSKeyCrossAccountTrustRule,
    S3CrossAccountTrustRule,
)
from cfripper.rules.ebs_volume_has_sse import EBSVolumeHasSSERule
from cfripper.rules.hardcoded_RDS_password import HardcodedRDSPasswordRule
from cfripper.rules.iam_roles import IAMRolesOverprivilegedRule, IAMRoleWildcardActionOnPolicyRule
from cfripper.rules.kms_key_wildcard_principal import KMSKeyWildcardPrincipalRule
from cfripper.rules.managed_policy_on_user import ManagedPolicyOnUserRule
from cfripper.rules.policy_on_user import PolicyOnUserRule
from cfripper.rules.privilege_escalation import PrivilegeEscalationRule
from cfripper.rules.s3_bucket_policy import S3BucketPolicyPrincipalRule
from cfripper.rules.s3_public_access import S3BucketPublicReadAclAndListStatementRule, S3BucketPublicReadWriteAclRule
from cfripper.rules.security_group import (
    SecurityGroupIngressOpenToWorldRule,
    SecurityGroupMissingEgressRule,
    SecurityGroupOpenToWorldRule,
)
from cfripper.rules.sns_topic_policy_not_principal import SNSTopicPolicyNotPrincipalRule
from cfripper.rules.sqs_queue_policy import SQSQueuePolicyNotPrincipalRule, SQSQueuePolicyPublicRule
from cfripper.rules.wildcard_policies import (
    S3BucketPolicyWildcardActionRule,
    SNSTopicPolicyWildcardActionRule,
    SQSQueuePolicyWildcardActionRule,
)
from cfripper.rules.wildcard_principals import FullWildcardPrincipalRule, PartialWildcardPrincipalRule

DEFAULT_RULES = {
    rule.__name__: rule
    for rule in (
        CloudFormationAuthenticationRule,
        CrossAccountTrustRule,
        EBSVolumeHasSSERule,
        FullWildcardPrincipalRule,
        HardcodedRDSPasswordRule,
        IAMRolesOverprivilegedRule,
        IAMRoleWildcardActionOnPolicyRule,
        KMSKeyCrossAccountTrustRule,
        KMSKeyWildcardPrincipalRule,
        ManagedPolicyOnUserRule,
        PartialWildcardPrincipalRule,
        PolicyOnUserRule,
        PrivilegeEscalationRule,
        S3BucketPolicyPrincipalRule,
        S3BucketPolicyWildcardActionRule,
        S3BucketPublicReadAclAndListStatementRule,
        S3BucketPublicReadWriteAclRule,
        S3CrossAccountTrustRule,
        SecurityGroupIngressOpenToWorldRule,
        SecurityGroupMissingEgressRule,
        SecurityGroupOpenToWorldRule,
        SNSTopicPolicyNotPrincipalRule,
        SNSTopicPolicyWildcardActionRule,
        SQSQueuePolicyNotPrincipalRule,
        SQSQueuePolicyPublicRule,
        SQSQueuePolicyWildcardActionRule,
    )
}

BASE_CLASSES = {rule.__name__: rule for rule in (CrossAccountCheckingRule, PrincipalCheckingRule)}
