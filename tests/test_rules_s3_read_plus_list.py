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
from cfripper.rules.S3BucketPublicReadAclAndListStatementRule import S3BucketPublicReadAclAndListStatementRule
from cfripper.s3_adapter import S3Adapter
from cfripper.model.result import Result


class TestS3BucketPublicReadAclAndListStatementRule:

    @pytest.fixture(scope="class")
    def template(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        cf_script = open("{}/test_templates/s3_read_plus_list.json".format(dir_path))
        cf_template = S3Adapter().convert_json_or_yaml_to_dict(cf_script.read())
        return pycfmodel.parse(cf_template)

    def test_with_test_template_wildcards(self, template):
        result = Result()
        rule = S3BucketPublicReadAclAndListStatementRule(None, result)

        rule.invoke(template.resources)

        assert result.valid
        assert len(result.failed_rules) == 0
        assert len(result.failed_monitored_rules) == 2
        assert result.failed_monitored_rules[0]["reason"] == "S3 Bucket S3Bucket should not have a public read acl and list bucket statement"
