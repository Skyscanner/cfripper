from cfripper.rules.base_rules import BaseDangerousPolicyActions, PrincipalCheckingRule, ResourceSpecificRule
from cfripper.rules.cloudformation_authentication import CloudFormationAuthenticationRule
from cfripper.rules.cross_account_trust import (
    CrossAccountCheckingRule,
    CrossAccountTrustRule,
    KMSKeyCrossAccountTrustRule,
    S3CrossAccountTrustRule,
)
from cfripper.rules.ebs_volume_has_sse import EBSVolumeHasSSERule
from cfripper.rules.ec2_security_group import (
    EC2SecurityGroupIngressOpenToWorldRule,
    EC2SecurityGroupMissingEgressRule,
    EC2SecurityGroupOpenToWorldRule,
)
from cfripper.rules.hardcoded_RDS_password import HardcodedRDSPasswordRule
from cfripper.rules.iam_roles import IAMRolesOverprivilegedRule, IAMRoleWildcardActionOnPolicyRule
from cfripper.rules.kms_key_wildcard_principal import KMSKeyWildcardPrincipalRule
from cfripper.rules.managed_policy_on_user import ManagedPolicyOnUserRule
from cfripper.rules.policy_on_user import PolicyOnUserRule
from cfripper.rules.privilege_escalation import PrivilegeEscalationRule
from cfripper.rules.s3_bucket_policy import S3BucketPolicyPrincipalRule
from cfripper.rules.s3_public_access import S3BucketPublicReadAclAndListStatementRule, S3BucketPublicReadWriteAclRule
from cfripper.rules.sns_topic_policy import SNSTopicDangerousPolicyActionsRule, SNSTopicPolicyNotPrincipalRule
from cfripper.rules.sqs_queue_policy import (
    SQSDangerousPolicyActionsRule,
    SQSQueuePolicyNotPrincipalRule,
    SQSQueuePolicyPublicRule,
)
from cfripper.rules.wildcard_policies import (
    S3BucketPolicyWildcardActionRule,
    SNSTopicPolicyWildcardActionRule,
    SQSQueuePolicyWildcardActionRule,
)
from cfripper.rules.wildcard_principals import FullWildcardPrincipalRule, PartialWildcardPrincipalRule
from cfripper.rules.wildcard_resource_rule import WildcardResourceRule

DEFAULT_RULES = {
    rule.__name__: rule
    for rule in (
        CloudFormationAuthenticationRule,
        CrossAccountTrustRule,
        EBSVolumeHasSSERule,
        EC2SecurityGroupIngressOpenToWorldRule,
        EC2SecurityGroupMissingEgressRule,
        EC2SecurityGroupOpenToWorldRule,
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
        SNSTopicDangerousPolicyActionsRule,
        SNSTopicPolicyNotPrincipalRule,
        SNSTopicPolicyWildcardActionRule,
        SQSDangerousPolicyActionsRule,
        SQSQueuePolicyNotPrincipalRule,
        SQSQueuePolicyPublicRule,
        SQSQueuePolicyWildcardActionRule,
        WildcardResourceRule,
    )
}

BASE_CLASSES = {
    rule.__name__: rule
    for rule in (BaseDangerousPolicyActions, CrossAccountCheckingRule, PrincipalCheckingRule, ResourceSpecificRule,)
}
