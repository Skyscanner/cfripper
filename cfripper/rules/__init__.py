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
from cfripper.rules.cross_account_trust import S3CrossAccountTrustRule
from cfripper.rules.s3_public_access import S3BucketPublicReadWriteAclRule
from cfripper.rules.security_group import SecurityGroupOpenToWorldRule
from cfripper.rules.sqs_queue_policy import SQSQueuePolicyPublicRule

from .cross_account_trust import CrossAccountTrustRule
from .ebs_volume_has_sse import EBSVolumeHasSSERule
from .hardcoded_RDS_password import HardcodedRDSPasswordRule
from .iam_roles import IAMRolesOverprivilegedRule
from .kms_key_wildcard_principal import KMSKeyWildcardPrincipal
from .managed_policy_on_user import ManagedPolicyOnUserRule
from .policy_on_user import PolicyOnUserRule
from .privilege_escalation import PrivilegeEscalationRule
from .s3_bucked_policy import S3BucketPolicyPrincipalRule
from .s3_public_access import S3BucketPublicReadAclAndListStatementRule
from .security_group import SecurityGroupIngressOpenToWorld
from .sns_topic_policy_not_principal import SNSTopicPolicyNotPrincipalRule
from .sqs_queue_policy import SQSQueuePolicyNotPrincipalRule
from .wildcard_principals import FullWildcardPrincipalRule, PartialWildcardPrincipalRule

DEFAULT_RULES = {
    "IAMRolesOverprivilegedRule": IAMRolesOverprivilegedRule,
    "SecurityGroupOpenToWorldRule": SecurityGroupOpenToWorldRule,
    "S3BucketPublicReadWriteAclRule": S3BucketPublicReadWriteAclRule,
    "SecurityGroupIngressOpenToWorld": SecurityGroupIngressOpenToWorld,
    "ManagedPolicyOnUserRule": ManagedPolicyOnUserRule,
    "PolicyOnUserRule": PolicyOnUserRule,
    "SNSTopicPolicyNotPrincipalRule": SNSTopicPolicyNotPrincipalRule,
    "SQSQueuePolicyNotPrincipalRule": SQSQueuePolicyNotPrincipalRule,
    "S3BucketPolicyPrincipalRule": S3BucketPolicyPrincipalRule,
    "EBSVolumeHasSSERule": EBSVolumeHasSSERule,
    "PrivilegeEscalationRule": PrivilegeEscalationRule,
    "CrossAccountTrustRule": CrossAccountTrustRule,
    "S3BucketPublicReadAclAndListStatementRule": S3BucketPublicReadAclAndListStatementRule,
    "SQSQueuePolicyPublicRule": SQSQueuePolicyPublicRule,
    "S3CrossAccountTrustRule": S3CrossAccountTrustRule,
    "HardcodedRDSPasswordRule": HardcodedRDSPasswordRule,
    "KMSKeyWildcardPrincipal": KMSKeyWildcardPrincipal,
    "FullWildcardPrincipal": FullWildcardPrincipalRule,
    "PartialWildcardPrincipal": PartialWildcardPrincipalRule,
}
