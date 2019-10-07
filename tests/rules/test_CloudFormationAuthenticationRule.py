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
import pytest
import pycfmodel
from cfripper.rules.CloudFormationAuthenticationRule import CloudFormationAuthenticationRule
from cfripper.model.result import Result


@pytest.fixture()
def template_bad():
    template = {
        "Parameters": {"subnetId": {"Type": "String", "Default": "subnet-4fd01116"}},
        "Resources": {
            "EC2I4LBA1": {
                "Type": "AWS::EC2::Instance",
                "Properties": {"ImageId": "ami-6df1e514", "InstanceType": "t2.micro", "SubnetId": {"Ref": "subnetId"}},
                "Metadata": {
                    "AWS::CloudFormation::Authentication": {
                        "testBasic": {
                            "type": "basic",
                            "username": "biff",
                            "password": "badpassword",
                            "uris": ["http://www.example.com/test"],
                        }
                    }
                },
            }
        },
    }
    return pycfmodel.parse(template).resolve()


@pytest.fixture()
def template_good():
    template = {
        "Parameters": {
            "subnetId": {"Type": "String", "Default": "subnet-4fd01116"},
            "MasterUsername": {
                "NoEcho": True,
                "Description": "The database admin account name",
                "MinLength": 8,
                "Type": "String",
            },
            "MasterUserPassword": {
                "NoEcho": True,
                "Description": "The database admin account password",
                "MinLength": 8,
                "Type": "String",
            },
        },
        "Resources": {
            "EC2I4LBA1": {
                "Type": "AWS::EC2::Instance",
                "Properties": {"ImageId": "ami-6df1e514", "InstanceType": "t2.micro", "SubnetId": {"Ref": "subnetId"}},
                "Metadata": {
                    "AWS::CloudFormation::Authentication": {
                        "testBasic": {
                            "type": "basic",
                            "username": {"Ref": "MasterUsername"},
                            "password": {"Ref": "MasterUserPassword"},
                            "uris": ["http://www.example.com/test"],
                        }
                    }
                },
            }
        },
    }

    return pycfmodel.parse(template).resolve()


def test_cfn_creds_found(template_bad):
    result = Result()
    rule = CloudFormationAuthenticationRule(None, result)

    rule.invoke(template_bad)

    assert not result.valid
    assert len(result.failed_rules) == 1
    assert len(result.failed_monitored_rules) == 0
    assert result.failed_rules[0]["reason"] == "Hardcoded credentials in EC2I4LBA1"


def test_cfn_valid(template_good):
    result = Result()
    rule = CloudFormationAuthenticationRule(None, result)

    rule.invoke(template_good)

    assert result.valid
    assert len(result.failed_rules) == 0
    assert len(result.failed_monitored_rules) == 0
