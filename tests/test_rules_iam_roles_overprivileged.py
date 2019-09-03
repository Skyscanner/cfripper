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
from unittest.mock import Mock
from cfripper.rules.IAMRolesOverprivilegedRule import IAMRolesOverprivilegedRule
from cfripper.model.result import Result


def test_with_valid_role_inline_policy():
    role_props = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "RootRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "Path": "/",
                    "Policies": [
                        {
                            "PolicyName": "chill_policy",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {"Effect": "Allow", "Action": ["ec2:DescribeInstances"], "Resource": "*"}
                                ],
                            },
                        }
                    ],
                },
            }
        },
    }

    resource = pycfmodel.parse(role_props).resources

    result = Result()
    rule = IAMRolesOverprivilegedRule(None, result)

    rule.check_managed_policies = Mock()

    rule.invoke(resource, [])
    rule.check_managed_policies.assert_called()

    assert result.valid
    assert len(result.failed_rules) == 0


def test_with_invalid_role_inline_policy():
    role_props = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "RootRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "Path": "/",
                    "Policies": [
                        {
                            "PolicyName": "not_so_chill_policy",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {"Effect": "Allow", "Action": ["ec2:DeleteInternetGateway"], "Resource": "*"}
                                ],
                            },
                        }
                    ],
                },
            }
        },
    }

    result = Result()
    rule = IAMRolesOverprivilegedRule(None, result)
    rule.check_managed_policies = Mock()
    resources = pycfmodel.parse(role_props).resources
    rule.invoke(resources, [])
    rule.check_managed_policies.assert_called()

    assert not result.valid
    assert (
        result.failed_rules[0]["reason"]
        == 'Role "RootRole" contains an insecure permission "ec2:DeleteInternetGateway" in policy "not_so_chill_policy"'
    )
    assert result.failed_rules[0]["rule"] == "IAMRolesOverprivilegedRule"


def test_with_invalid_role_inline_policy_resource_as_array():
    role_props = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "RootRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "Path": "/",
                    "Policies": [
                        {
                            "PolicyName": "not_so_chill_policy",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {"Effect": "Allow", "Action": ["ec2:DeleteInternetGateway"], "Resource": ["*"]}
                                ],
                            },
                        }
                    ],
                },
            }
        },
    }

    result = Result()
    rule = IAMRolesOverprivilegedRule(None, result)
    rule.check_managed_policies = Mock()
    resources = pycfmodel.parse(role_props).resources
    rule.invoke(resources, [])
    rule.check_managed_policies.assert_called()

    assert not result.valid
    assert (
        result.failed_rules[0]["reason"]
        == 'Role "RootRole" contains an insecure permission "ec2:DeleteInternetGateway" in policy "not_so_chill_policy"'
    )
    assert result.failed_rules[0]["rule"] == "IAMRolesOverprivilegedRule"


def test_with_valid_role_managed_policy():
    role_props = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "RootRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {"Path": "/", "ManagedPolicyArns": ["arn:aws:iam::aws:policy/YadaYadaYada"]},
            }
        },
    }

    result = Result()
    rule = IAMRolesOverprivilegedRule(None, result)
    rule.check_inline_policies = Mock()
    resources = pycfmodel.parse(role_props).resources
    rule.invoke(resources, [])
    rule.check_inline_policies.assert_called()

    assert result.valid
    assert len(result.failed_rules) == 0


def test_with_invalid_role_managed_policy():
    role_props = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "RootRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {"Path": "/", "ManagedPolicyArns": ["arn:aws:iam::aws:policy/AdministratorAccess"]},
            }
        },
    }

    result = Result()
    rule = IAMRolesOverprivilegedRule(None, result)
    resources = pycfmodel.parse(role_props).resources
    rule.invoke(resources, [])

    assert not result.valid
    assert (
        result.failed_rules[0]["reason"]
        == "Role RootRole has forbidden Managed Policy arn:aws:iam::aws:policy/AdministratorAccess"
    )
    assert result.failed_rules[0]["rule"] == "IAMRolesOverprivilegedRule"


def test_with_invalid_role_inline_policy_fn_if():
    role_props = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "RootRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "Path": "/",
                    "Policies": [
                        {
                            "Fn::If": [
                                "IsSandbox",
                                {
                                    "PolicyDocument": {
                                        "Statement": [
                                            {
                                                "Action": "sts:AssumeRole",
                                                "Effect": "Allow",
                                                "Resource": "arn:aws:iam::325714046698:role/sandbox-secrets-access",
                                            }
                                        ],
                                        "Version": "2012-10-17",
                                    },
                                    "PolicyName": "SandboxSecretsAccessAssumerole",
                                },
                                {
                                    "PolicyDocument": {
                                        "Statement": [
                                            {"Action": ["ec2:DeleteVpc"], "Effect": "Allow", "Resource": ["*"]}
                                        ],
                                        "Version": "2012-10-17",
                                    },
                                    "PolicyName": "ProdCredentialStoreAccessPolicy",
                                },
                            ]
                        }
                    ],
                },
            }
        },
    }

    result = Result()
    rule = IAMRolesOverprivilegedRule(None, result)
    rule.check_managed_policies = Mock()
    resources = pycfmodel.parse(role_props).resources
    rule.invoke(resources, [])
    rule.check_managed_policies.assert_called()

    assert not result.valid
    assert (
        result.failed_rules[0]["reason"]
        == 'Role "RootRole" contains an insecure permission "ec2:DeleteVpc" in policy "ProdCredentialStoreAccessPolicy"'
    )
    assert result.failed_rules[0]["rule"] == "IAMRolesOverprivilegedRule"
