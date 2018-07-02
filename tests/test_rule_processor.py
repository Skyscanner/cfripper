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


from unittest.mock import Mock
from cfripper.model.rule_processor import RuleProcessor


EXAMPLE_CF_TEMPLATE = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Resources": {
        "slingshotLambdaExecutionRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                      {
                          "Effect": "Allow",
                          "Principal": {
                              "Service": [
                                  "lambda.amazonaws.com"
                              ]
                          },
                          "Action": [
                              "sts:AssumeRole"
                          ]
                      }
                    ]
                },
                "Path": "/",
                "Policies": [
                    {
                        "PolicyName": "vpc_access",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": [
                                      "logs:CreateLogGroup",
                                      "logs:CreateLogStream",
                                      "logs:PutLogEvents",
                                      "ec2:CreateNetworkInterface",
                                      "ec2:DescribeNetworkInterfaces",
                                      "ec2:DeleteNetworkInterface"
                                    ],
                                    "Resource": "*"
                                }
                            ]
                        }
                    },
                    {
                        "PolicyName": "AWSXrayWriteOnlyAccess",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": [
                                      "xray:PutTraceSegments",
                                      "xray:PutTelemetryRecords"
                                    ],
                                    "Resource": [
                                        "*"
                                    ]
                                }
                            ]
                        }
                    }
                ]
            }
        }
    }
}


class TestRuleProcessor:

    def test_with_no_rules(self):
        processor = RuleProcessor()
        config = Mock()
        result = Mock()

        processor.process_cf_template(EXAMPLE_CF_TEMPLATE, config, result)

    def test_with_mock_rule(self):
        rule = Mock()

        processor = RuleProcessor(
            rule
        )

        config = Mock()
        result = Mock()
        processor.process_cf_template(EXAMPLE_CF_TEMPLATE, config, result)

        rule.invoke.assert_called()
