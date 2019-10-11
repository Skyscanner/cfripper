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
import pytest

from cfripper.model.rule_processor import Rule
from cfripper.rules.S3BucketPublicReadAclAndListStatementRule import S3BucketPublicReadAclAndListStatementRule
from cfripper.model.result import Result
from tests.utils import get_cfmodel_from


@pytest.fixture()
def s3_read_plus_list():
    return get_cfmodel_from("rules/S3BucketPublicReadAclAndListStatementRule/s3_read_plus_list.json").resolve()


def test_s3_read_plus_list(s3_read_plus_list):
    result = Result()
    rule = S3BucketPublicReadAclAndListStatementRule(None, result)
    rule.invoke(s3_read_plus_list)

    assert not result.valid
    assert len(result.failed_rules) == 1
    assert len(result.failed_monitored_rules) == 0
    assert result.failed_monitored_rules[0]["rule"] == "S3BucketPublicReadAclAndListStatementRule"
    assert (
        result.failed_monitored_rules[0]["reason"]
        == "S3 Bucket S3Bucket should not have a public read acl and list bucket statement"
    )
    assert result.failed_monitored_rules[0]["rule_mode"] == Rule.DEBUG
