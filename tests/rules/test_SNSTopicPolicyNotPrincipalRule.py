"""
Copyright 2018-2020 Skyscanner Ltd

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
from cfripper.rules import SNSTopicPolicyNotPrincipalRule
from tests.utils import get_cfmodel_from


@pytest.fixture()
def s3_bucket_with_wildcards():
    return get_cfmodel_from("rules/SNSTopicPolicyNotPrincipalRule/bad_template.json").resolve()


def test_s3_bucket_with_wildcards(s3_bucket_with_wildcards):
    result = Result()
    rule = SNSTopicPolicyNotPrincipalRule(None, result)
    rule.invoke(s3_bucket_with_wildcards)

    assert result.valid
    assert len(result.failed_rules) == 0
    assert len(result.failed_monitored_rules) == 1
    assert result.failed_monitored_rules[0].rule == "SNSTopicPolicyNotPrincipalRule"
    assert (
        result.failed_monitored_rules[0].reason
        == "SNS Topic mysnspolicyA policy should not allow Allow and NotPrincipal at the same time"
    )
