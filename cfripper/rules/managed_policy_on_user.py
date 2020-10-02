__all__ = ["ManagedPolicyOnUserRule"]

from typing import Dict, Optional

from pycfmodel.model.cf_model import CFModel
from pycfmodel.model.resources.iam_managed_policy import IAMManagedPolicy

from cfripper.model.enums import RuleGranularity
from cfripper.model.result import Result
from cfripper.rules.base_rules import Rule


class ManagedPolicyOnUserRule(Rule):
    """
    Checks if any IAM managed policy is applied to a group and not a user.

    Risk:
        Instead of defining permissions for individual IAM users, it's usually more convenient and secure
        to create [IAM groups](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_groups.html) that relate
        to different functions. IAM users can be assigned to these groups.
        All the users in an IAM group inherit the permissions assigned to the group. That way, you can make
        changes for everyone in a group in just one place. As people move around in your company, you can
        simply change what IAM group their IAM user belongs to, without risking a user having too much
        privilege.

    Fix:
        Use IAM Groups as opposed to users in IAM Managed Policies.

    Code for fix:
        This is an example which will be flagged by CFRipper:

        ```json
        "BadPolicy": {
          "Type": "AWS::IAM::ManagedPolicy",
          "Properties": {
            "Description": "Policy for something.",
            "Path": "/",
            "PolicyDocument": {
              "Version": "2012-10-17",
              "Statement": [...]
            },
            "Users": [{"Ref": "TestUser"}]
          }
        }
        ```

        This is an example of a more acceptable CloudFormation policy:

        ```json
        "GoodPolicy": {
          "Type": "AWS::IAM::ManagedPolicy",
          "Properties": {
            "Description": "Policy for something.",
            "Path": "/",
            "PolicyDocument": {
              "Version": "2012-10-17",
              "Statement": [...]
            },
            "Groups": ["user_group"]
          }
        }
        ```
    """

    REASON = "IAM managed policy {} should not apply directly to users. Should be on group"
    GRANULARITY = RuleGranularity.RESOURCE

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, IAMManagedPolicy) and resource.Properties.Users:
                self.add_failure_to_result(result, self.REASON.format(logical_id), resource_ids={logical_id})
        return result
