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
from cfripper.rules.cloudformation_authentication import *  # noqa: F403
from cfripper.rules.cross_account_trust import *  # noqa: F403
from cfripper.rules.ebs_volume_has_sse import *  # noqa: F403
from cfripper.rules.hardcoded_RDS_password import *  # noqa: F403
from cfripper.rules.iam_managed_policy_wildcard_action import *  # noqa: F403
from cfripper.rules.iam_roles import *  # noqa: F403
from cfripper.rules.kms_key_wildcard_principal import *  # noqa: F403
from cfripper.rules.managed_policy_on_user import *  # noqa: F403
from cfripper.rules.policy_on_user import *  # noqa: F403
from cfripper.rules.privilege_escalation import *  # noqa: F403
from cfripper.rules.s3_bucket_policy import *  # noqa: F403
from cfripper.rules.s3_public_access import *  # noqa: F403
from cfripper.rules.security_group import *  # noqa: F403
from cfripper.rules.sns_topic_policy_not_principal import *  # noqa: F403
from cfripper.rules.sqs_queue_policy import *  # noqa: F403
from cfripper.rules.wildcard_principals import *  # noqa: F403

DEFAULT_RULES = {
    "IAMRolesOverprivilegedRule": IAMRolesOverprivilegedRule,  # noqa: F405
    "SecurityGroupOpenToWorldRule": SecurityGroupOpenToWorldRule,  # noqa: F405
    "S3BucketPublicReadWriteAclRule": S3BucketPublicReadWriteAclRule,  # noqa: F405
    "SecurityGroupIngressOpenToWorld": SecurityGroupIngressOpenToWorld,  # noqa: F405
    "ManagedPolicyOnUserRule": ManagedPolicyOnUserRule,  # noqa: F405
    "PolicyOnUserRule": PolicyOnUserRule,  # noqa: F405
    "SNSTopicPolicyNotPrincipalRule": SNSTopicPolicyNotPrincipalRule,  # noqa: F405
    "SQSQueuePolicyNotPrincipalRule": SQSQueuePolicyNotPrincipalRule,  # noqa: F405
    "S3BucketPolicyPrincipalRule": S3BucketPolicyPrincipalRule,  # noqa: F405
    "EBSVolumeHasSSERule": EBSVolumeHasSSERule,  # noqa: F405
    "PrivilegeEscalationRule": PrivilegeEscalationRule,  # noqa: F405
    "CrossAccountTrustRule": CrossAccountTrustRule,  # noqa: F405
    "S3BucketPublicReadAclAndListStatementRule": S3BucketPublicReadAclAndListStatementRule,  # noqa: F405
    "SQSQueuePolicyPublicRule": SQSQueuePolicyPublicRule,  # noqa: F405
    "S3CrossAccountTrustRule": S3CrossAccountTrustRule,  # noqa: F405
    "HardcodedRDSPasswordRule": HardcodedRDSPasswordRule,  # noqa: F405
    "KMSKeyWildcardPrincipal": KMSKeyWildcardPrincipal,  # noqa: F405
    "FullWildcardPrincipal": FullWildcardPrincipalRule,  # noqa: F405
    "PartialWildcardPrincipal": PartialWildcardPrincipalRule,  # noqa: F405
}
