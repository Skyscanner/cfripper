"""
Copyright 2018 Skyscanner Ltd

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
"""


from cfripper.rules.IAMRolesOverprivilegedRule import IAMRolesOverprivilegedRule
from cfripper.rules.SecurityGroupOpenToWorldRule import SecurityGroupOpenToWorldRule
from cfripper.rules.SecurityGroupIngressOpenToWorld import SecurityGroupIngressOpenToWorld
from cfripper.rules.S3BucketPublicReadWriteAclRule import S3BucketPublicReadWriteAclRule
from cfripper.rules.ManagedPolicyOnUserRule import ManagedPolicyOnUserRule
from cfripper.rules.PolicyOnUserRule import PolicyOnUserRule
from cfripper.rules.SNSTopicPolicyNotPrincipalRule import SNSTopicPolicyNotPrincipalRule
from cfripper.rules.SQSQueuePolicyNotPrincipalRule import SQSQueuePolicyNotPrincipalRule
from cfripper.rules.S3BucketPolicyPrincipalRule import S3BucketPolicyPrincipalRule
from cfripper.rules.EBSVolumeHasSSERule import EBSVolumeHasSSERule
from cfripper.rules.PrivilegeEscalationRule import PrivilegeEscalationRule
from cfripper.rules.CrossAccountTrustRule import CrossAccountTrustRule
from cfripper.rules.S3BucketPublicReadAclAndListStatementRule import S3BucketPublicReadAclAndListStatementRule
from cfripper.rules.SQSQueuePolicyPublicRule import SQSQueuePolicyPublicRule
from cfripper.rules.S3CrossAccountTrustRule import S3CrossAccountTrustRule
from cfripper.rules.HardcodedRDSPasswordRule import HardcodedRDSPasswordRule

ALL_RULES = {
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
}
