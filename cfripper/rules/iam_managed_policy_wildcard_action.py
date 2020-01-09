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
__all__ = ["IAMManagedPolicyWildcardActionRule"]
from pycfmodel.model.resources.iam_managed_policy import IAMManagedPolicy

from cfripper.config.regex import REGEX_WILDCARD_POLICY_ACTION
from cfripper.model.enums import RuleGranularity
from cfripper.model.rule import Rule


class IAMManagedPolicyWildcardActionRule(Rule):
    """
    Checks all actions of IAM roles in a CloudFormation file for any `Resource: *`,
    and compares policies to a list of blacklisted roles, such as `administratoraccess`.
    See [current blacklisted roles](https://github.com/Skyscanner/cfripper/blob/master/cfripper/config/config.py#L26).

    Risk:
        The principle of least privilege (POLP), an important concept in computer security, is the
        practice of limiting access rights for users to the bare minimum permissions they need to
        perform their work.

    Fix:
        Do not use a wildcard on resources for actions that are in the blacklist. The example below
        shows a compliant policy, and in the code comments, an example of a non-compliant policy.

    Code for fix:
        This is an example of a compliant policy, and commented out is the violation that triggered the rule:

        ````json
        {
            "PolicyName": "not_so_chill_policy",
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "ec2:DeleteInternetGateway"
                        ],
                        "Resource": [
                            // non-compliant example below:
                            // "*"
                            // compliant example where Resource has been better defined
                            "arn:aws:ec2:::some-ec2-thing/*"
                        ]
                    }
                ]
            }
        }
        ````

        Managed policy ARNs can also be dangerous and allow more privilege to a service than required. These should be avoided:
        ````json
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "RootRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "Path": "/",
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": "*",
                                    "Action": [
                                        "sts:AssumeRole"
                                    ]
                                }
                            ]
                        },
                        "ManagedPolicyArns": [
                            "arn:aws:iam::aws:policy/AdministratorAccess"
                        ]
                    }
                }
            }
        }
        ````
    """

    GRANULARITY = RuleGranularity.RESOURCE
    REASON = "IAM managed policy {} should not allow * action"

    def invoke(self, cfmodel):
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, IAMManagedPolicy) and resource.Properties.PolicyDocument.allowed_actions_with(
                REGEX_WILDCARD_POLICY_ACTION
            ):
                self.add_failure(type(self).__name__, self.REASON.format(logical_id), resource_ids={logical_id})
