## Available Rules

* CloudFormationAuthenticationRule
* CrossAccountCheckingRule
* CrossAccountTrustRule
* EBSVolumeHasSSERule
* FullWildcardPrincipalRule
* GenericWildcardPrincipalRule
* HardcodedRDSPasswordRule
* IAMManagedPolicyWildcardActionRule
* IAMRolesOverprivilegedRule
* IAMRoleWildcardActionOnPermissionsPolicyRule
* IAMRoleWildcardActionOnTrustPolicyRule
* KMSKeyWildcardPrincipal
* ManagedPolicyOnUserRule
* PartialWildcardPrincipalRule
* PolicyOnUserRule
* PrivilegeEscalationRule
* S3BucketPolicyPrincipalRule
* S3BucketPolicyWildcardActionRule
* S3BucketPublicReadAclAndListStatementRule
* S3BucketPublicReadWriteAclRule
* S3CrossAccountTrustRule
* SecurityGroupIngressOpenToWorld
* SecurityGroupMissingEgressRule
* SecurityGroupOpenToWorldRule
* SNSTopicPolicyNotPrincipalRule
* SQSQueuePolicyNotPrincipalRule
* SQSQueuePolicyPublicRule
* SQSQueuePolicyWildcardActionRule


## Custom Rules

To add custom rules first extend the [Rule](https://github.com/Skyscanner/cfripper/blob/master/cfripper/model/rule.py)
 class. Then implement the `invoke` method by adding your logic.
 
```python
    @abstractmethod
    def invoke(self, cfmodel: CFModel):
        pass
```

CFripper uses [pycfmodel](https://github.com/Skyscanner/pycfmodel) to create a Python model of the CloudFormation script.
 This model is passed to the `invoke` function as the `resources` parameter. You can use the model's iterate through the
 resources and other objects of the model and use the helper functions to perform various checks. Look at the
 [current rules](cfripper/rules) for examples.

```python
class S3CrossAccountTrustRule(CrossAccountCheckingRule):

    REASON = "{} has forbidden cross-account policy allow with {} for an S3 bucket."

    def invoke(self, cfmodel):
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, S3BucketPolicy):
                for statement in resource.Properties.PolicyDocument._statement_as_list():
                    self._do_statement_check(logical_id, statement)
```

## Monitor Mode
By default, each rule has `MONITOR_MODE` set to false. Monitor model will return the failed rules in another field in the
 response, instead in the main "failed rules". This way new rules can be tested before they are removed from monitor 
 mode and start triggering alarms.
