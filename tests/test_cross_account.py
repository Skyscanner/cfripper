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
from cfripper.rules.CrossAccountTrustRule import CrossAccountTrustRule
from cfripper.config.config import Config
from cfripper.model.result import Result


test_template = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Resources": {
        "RootRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {
                                "AWS": [
                                    "arn:aws:iam::123456789:user/someuser@bla.com",
                                    "arn:aws:iam::123456789:user/someuser@bla.com",
                                    "arn:aws:iam::123456789:user/someuser@bla.com",
                                    "arn:aws:iam::123456789:user/someuser@bla.com",
                                    "arn:aws:iam::123456789:root",
                                    "arn:aws:iam::999999999:role/someuser@bla.com",
                                    "arn:aws:iam::123456789:user/someuser@bla.com",
                                    "arn:aws:iam::123456789:user/someuser@bla.com",
                                    "arn:aws:iam::123456789:user/someuser@bla.com",
                                    "arn:aws:iam::123456789:user/someuser@bla.com",
                                ]
                            },
                            "Action": "sts:AssumeRole",
                        }
                    ],
                },
                "Path": "/",
                "Policies": [],
            },
        }
    },
}


class TestCrossAccountTrustRule:
    @pytest.fixture(scope="class")
    def template(self):
        return pycfmodel.parse(test_template)

    def test_with_test_template_wildcards(self, template):
        result = Result()
        rule = CrossAccountTrustRule(Config(aws_account_id="123456789"), result)

        rule.invoke(template.resources, template.parameters)

        assert not result.valid
        assert len(result.failed_rules) == 2
        assert len(result.failed_monitored_rules) == 0
        assert (
            result.failed_rules[0]["reason"]
            == "RootRole has forbidden cross-account trust relationship with arn:aws:iam::123456789:root"
        )
        assert (
            result.failed_rules[1]["reason"]
            == "RootRole has forbidden cross-account trust relationship with arn:aws:iam::999999999:role/someuser@bla.com"
        )
