"""
Copyright 2019 Skyscanner Ltd

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
"""


import os
import pytest
import pycfmodel

from cfripper.config.config import Config
from cfripper.rules.S3CrossAccountTrustRule import S3CrossAccountTrustRule
from cfripper.model.result import Result
from cfripper.model.utils import convert_json_or_yaml_to_dict


class TestS3CrossAccountTrustRule:
    @pytest.fixture(scope="class")
    def template(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(f"{dir_path}/test_templates/s3_bucket_cross_account.json") as cf_script:
            cf_template = convert_json_or_yaml_to_dict(cf_script.read())
        return pycfmodel.parse(cf_template)

    def test_with_cross_account_in_bucket_policy(self, template):
        result = Result()
        rule = S3CrossAccountTrustRule(Config(aws_account_id="123456789"), result)

        rule.invoke(template.resources, template.parameters)

        assert not result.valid
        assert len(result.failed_rules) == 1
        assert len(result.failed_monitored_rules) == 0
        assert (
            result.failed_rules[0]["reason"]
            == "S3BucketPolicyAccountAccess has forbidden cross-account policy allow with arn:aws:iam::987654321:root for an S3 bucket."
        )


class TestS3CrossAccountTrustRuleWithNormalAccess:
    @pytest.fixture(scope="class")
    def template(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(f"{dir_path}/test_templates/s3_bucket_cross_account_and_normal.json") as cf_script:
            cf_template = convert_json_or_yaml_to_dict(cf_script.read())
        return pycfmodel.parse(cf_template)

    def test_with_cross_account_in_bucket_policy(self, template):
        result = Result()
        rule = S3CrossAccountTrustRule(Config(aws_account_id="123456789"), result)

        rule.invoke(template.resources, template.parameters)

        assert not result.valid
        assert len(result.failed_rules) == 1
        assert len(result.failed_monitored_rules) == 0
        assert (
            result.failed_rules[0]["reason"]
            == "S3BucketPolicyAccountAccess has forbidden cross-account policy allow with arn:aws:iam::666555444:root for an S3 bucket."
        )
