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
import os
import pycfmodel
from cfripper.rules.S3BucketPolicyWildcardActionRule import S3BucketPolicyWildcardActionRule
from cfripper.model.utils import convert_json_or_yaml_to_dict
from cfripper.model.result import Result


class TestS3BucketPolicyWildcardActionRule:
    @pytest.fixture(scope="class")
    def template(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(f"{dir_path}/test_templates/s3_bucket_with_wildcards.json") as cf_script:
            cf_template = convert_json_or_yaml_to_dict(cf_script.read())
        return pycfmodel.parse(cf_template)

    def test_with_test_template_wildcards(self, template):
        result = Result()
        rule = S3BucketPolicyWildcardActionRule(None, result)

        rule.invoke(template.resources, template.parameters)

        assert not result.valid
        assert len(result.failed_rules) == 2
        assert len(result.failed_monitored_rules) == 0
        assert result.failed_rules[0]["reason"] == "S3 Bucket policy S3BucketPolicy should not allow * action"