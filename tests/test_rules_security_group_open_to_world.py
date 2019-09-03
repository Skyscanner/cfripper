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


from pycfmodel.core import parse

from cfripper.rules.SecurityGroupOpenToWorldRule import SecurityGroupOpenToWorldRule
from cfripper.model.result import Result


class TestSecurityGroupOpenToWorldRule:
    def test_security_group_type_slash0(self):
        role_props = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "RootRole": {
                    "Type": "AWS::EC2::SecurityGroup",
                    "Properties": {"SecurityGroupIngress": [{"CidrIp": "0.0.0.0/0", "FromPort": 22, "ToPort": 22}]},
                }
            },
        }

        result = Result()
        rule = SecurityGroupOpenToWorldRule(None, result)
        resources = parse(role_props).resources
        rule.invoke(resources, [])

        assert not result.valid
        assert result.failed_rules[0]["reason"] == 'Port 22 open to the world in security group "RootRole"'
        assert result.failed_rules[0]["rule"] == "SecurityGroupOpenToWorldRule"

    def test_valid_security_group_not_slash0(self):
        role_props = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "RootRole": {
                    "Type": "AWS::EC2::SecurityGroup",
                    "Properties": {"SecurityGroupIngress": [{"CidrIp": "10.0.0.0/8", "FromPort": 22, "ToPort": 22}]},
                }
            },
        }

        result = Result()
        rule = SecurityGroupOpenToWorldRule(None, result)
        resources = parse(role_props).resources
        rule.invoke(resources, [])

        assert result.valid
        assert len(result.failed_rules) == 0

    def test_valid_security_group_port80(self):
        role_props = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "RootRole": {
                    "Type": "AWS::EC2::SecurityGroup",
                    "Properties": {"SecurityGroupIngress": [{"CidrIp": "0.0.0.0/0", "FromPort": 80, "ToPort": 80}]},
                }
            },
        }

        result = Result()
        rule = SecurityGroupOpenToWorldRule(None, result)
        resources = parse(role_props).resources
        rule.invoke(resources, [])

        assert result.valid
        assert len(result.failed_rules) == 0

    def test_valid_security_group_port443(self):
        role_props = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "RootRole": {
                    "Type": "AWS::EC2::SecurityGroup",
                    "Properties": {"SecurityGroupIngress": [{"CidrIp": "0.0.0.0/0", "FromPort": 443, "ToPort": 443}]},
                }
            },
        }

        result = Result()
        rule = SecurityGroupOpenToWorldRule(None, result)
        resources = parse(role_props).resources
        rule.invoke(resources, [])

        assert result.valid
        assert len(result.failed_rules) == 0

    def test_invalid_security_group_cidripv6(self):
        role_props = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "RootRole": {
                    "Type": "AWS::EC2::SecurityGroup",
                    "Properties": {"SecurityGroupIngress": [{"CidrIpv6": "::/0", "FromPort": 22, "ToPort": 22}]},
                }
            },
        }

        result = Result()
        rule = SecurityGroupOpenToWorldRule(None, result)
        resources = parse(role_props).resources
        rule.invoke(resources, [])

        assert result.failed_rules[0]["reason"] == 'Port 22 open to the world in security group "RootRole"'
        assert result.failed_rules[0]["rule"] == "SecurityGroupOpenToWorldRule"

    def test_invalid_security_group_range(self):
        role_props = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "RootRole": {
                    "Type": "AWS::EC2::SecurityGroup",
                    "Properties": {"SecurityGroupIngress": [{"CidrIp": "0.0.0.0/0", "FromPort": 0, "ToPort": 100}]},
                }
            },
        }

        result = Result()
        rule = SecurityGroupOpenToWorldRule(None, result)
        resources = parse(role_props).resources
        rule.invoke(resources, [])

        assert result.failed_rules[0]["reason"] == "Ports 0 - 100 open in Security Group RootRole"
        assert result.failed_rules[0]["rule"] == "SecurityGroupOpenToWorldRule"

    def test_invalid_security_group_multiple_statements(self):
        role_props = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "RootRole": {
                    "Type": "AWS::EC2::SecurityGroup",
                    "Properties": {
                        "SecurityGroupIngress": [
                            {"CidrIp": "10.0.0.0/8", "FromPort": 22, "ToPort": 22},
                            {"CidrIp": "0.0.0.0/0", "FromPort": 9090, "ToPort": 9090},
                        ]
                    },
                }
            },
        }

        result = Result()
        rule = SecurityGroupOpenToWorldRule(None, result)
        resources = parse(role_props).resources
        rule.invoke(resources, [])

        assert result.failed_rules[0]["reason"] == 'Port 9090 open to the world in security group "RootRole"'
        assert result.failed_rules[0]["rule"] == "SecurityGroupOpenToWorldRule"

    def test_security_group_rules_as_refs(self):

        role_props = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "RootRole": {
                    "Type": "AWS::EC2::SecurityGroup",
                    "Properties": {
                        "SecurityGroupIngress": [{"CidrIp": {"Ref": "MyParam"}, "FromPort": 22, "ToPort": 22}]
                    },
                }
            },
        }

        result = Result()
        rule = SecurityGroupOpenToWorldRule(None, result)
        resources = parse(role_props).resources
        rule.invoke(resources, [])

        assert result.valid
        assert len(result.failed_rules) == 0
