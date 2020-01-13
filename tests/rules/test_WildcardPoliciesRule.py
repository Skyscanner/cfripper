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
from unittest.mock import patch

import pytest

from cfripper.model.result import Result
from cfripper.rules.wildcard_policies import (
    GenericWildcardPolicyRule,
    S3BucketPolicyWildcardActionRule,
    SQSQueuePolicyWildcardActionRule,
)
from tests.utils import get_cfmodel_from


@pytest.fixture()
def s3_bucket_with_wildcards():
    return get_cfmodel_from("rules/WildcardPoliciesRule/s3_bucket_with_wildcards.json").resolve()


@pytest.fixture()
def sqs_queue_with_wildcards():
    return get_cfmodel_from("rules/WildcardPoliciesRule/sqs_queue_with_wildcards.json").resolve()


@patch("cfripper.rules.wildcard_policies.logger.warning")
def test_invoking_general_rule_not_allowed(mock_logger, s3_bucket_with_wildcards):
    result = Result()
    rule = GenericWildcardPolicyRule(None, result)
    rule.invoke(s3_bucket_with_wildcards)

    assert result.valid
    assert len(result.failed_rules) == 0
    assert len(result.failed_monitored_rules) == 0

    mock_logger.assert_called_once_with("Not running GenericWildcardPolicyRule rule as AWS_RESOURCE is not defined.")


def test_s3_bucket_with_wildcards(s3_bucket_with_wildcards):
    result = Result()
    rule = S3BucketPolicyWildcardActionRule(None, result)
    rule.invoke(s3_bucket_with_wildcards)

    assert result.valid
    assert len(result.failed_rules) == 0
    assert len(result.failed_monitored_rules) == 2
    assert result.failed_monitored_rules[0].rule == "S3BucketPolicyWildcardActionRule"
    assert result.failed_monitored_rules[0].reason == "The S3BucketPolicy S3BucketPolicy should not allow a `*` action"


def test_sqs_queue_with_wildcards(sqs_queue_with_wildcards):
    result = Result()
    rule = SQSQueuePolicyWildcardActionRule(None, result)
    rule.invoke(sqs_queue_with_wildcards)

    assert result.valid
    assert len(result.failed_rules) == 0
    assert len(result.failed_monitored_rules) == 4
    assert result.failed_monitored_rules[0].rule == "SQSQueuePolicyWildcardActionRule"
    assert result.failed_monitored_rules[0].reason == "The SQSQueuePolicy mysqspolicy1 should not allow a `*` action"
    assert result.failed_monitored_rules[1].rule == "SQSQueuePolicyWildcardActionRule"
    assert result.failed_monitored_rules[1].reason == "The SQSQueuePolicy mysqspolicy1b should not allow a `*` action"
    assert result.failed_monitored_rules[2].rule == "SQSQueuePolicyWildcardActionRule"
    assert result.failed_monitored_rules[2].reason == "The SQSQueuePolicy mysqspolicy1c should not allow a `*` action"
    assert result.failed_monitored_rules[3].rule == "SQSQueuePolicyWildcardActionRule"
    assert result.failed_monitored_rules[3].reason == "The SQSQueuePolicy mysqspolicy1d should not allow a `*` action"
