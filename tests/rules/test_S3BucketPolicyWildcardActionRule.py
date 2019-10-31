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

from cfripper.model.result import Result
from cfripper.rules.S3BucketPolicyWildcardActionRule import S3BucketPolicyWildcardActionRule
from tests.utils import get_cfmodel_from


@pytest.fixture()
def s3_bucket_with_wildcards():
    return get_cfmodel_from("rules/S3BucketPolicyWildcardActionRule/s3_bucket_with_wildcards.json").resolve()


def test_s3_bucket_with_wildcards(s3_bucket_with_wildcards):
    result = Result()
    rule = S3BucketPolicyWildcardActionRule(None, result)
    rule.invoke(s3_bucket_with_wildcards)

    assert not result.valid
    assert len(result.failed_rules) == 2
    assert len(result.failed_monitored_rules) == 0
    assert result.failed_rules[0].rule == "S3BucketPolicyWildcardActionRule"
    assert result.failed_rules[0].reason == "S3 Bucket policy S3BucketPolicy should not allow * action"
