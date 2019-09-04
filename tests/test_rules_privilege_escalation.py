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


import pycfmodel
from cfripper.rules.PrivilegeEscalationRule import PrivilegeEscalationRule
from cfripper.model.result import Result


def test_with_valid_role_inline_policy():
    role_props = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "RootRole": {
                "Type": "AWS::IAM::Policy",
                "Properties": {
                    "PolicyName": "root",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": ["IAM:CREATEPOLICY"],
                                "Resource": ["arn:aws:glue:eu-west-1:12345678:catalog"],
                            }
                        ],
                    },
                    "Roles": "some_role",
                },
            }
        },
    }

    resource = pycfmodel.parse(role_props).resources

    result = Result()
    rule = PrivilegeEscalationRule(None, result)

    rule.invoke(resource, [])

    assert not result.valid
    assert len(result.failed_rules) == 1
