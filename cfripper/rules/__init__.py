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
from .CrossAccountTrustRule import CrossAccountTrustRule
from .EBSVolumeHasSSERule import EBSVolumeHasSSERule
from .FullWildcardPrincipalRule import FullWildcardPrincipalRule
from .HardcodedRDSPasswordRule import HardcodedRDSPasswordRule
from .IAMRolesOverprivilegedRule import IAMRolesOverprivilegedRule
from .KMSKeyWildcardPrincipal import KMSKeyWildcardPrincipal
from .ManagedPolicyOnUserRule import ManagedPolicyOnUserRule
from .PartialWildcardPrincipal import PartialWildcardPrincipalRule
from .PolicyOnUserRule import PolicyOnUserRule
from .PrivilegeEscalationRule import PrivilegeEscalationRule
from .S3BucketPolicyPrincipalRule import S3BucketPolicyPrincipalRule
from .S3BucketPublicReadAclAndListStatementRule import S3BucketPublicReadAclAndListStatementRule
from .S3BucketPublicReadWriteAclRule import S3BucketPublicReadWriteAclRule
from .S3CrossAccountTrustRule import S3CrossAccountTrustRule
from .SecurityGroupIngressOpenToWorld import SecurityGroupIngressOpenToWorld
from .SecurityGroupOpenToWorldRule import SecurityGroupOpenToWorldRule
from .SNSTopicPolicyNotPrincipalRule import SNSTopicPolicyNotPrincipalRule
from .SQSQueuePolicyNotPrincipalRule import SQSQueuePolicyNotPrincipalRule
from .SQSQueuePolicyPublicRule import SQSQueuePolicyPublicRule

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
