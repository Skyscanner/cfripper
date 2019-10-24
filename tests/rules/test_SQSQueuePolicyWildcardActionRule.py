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

from cfripper.rules.SQSQueuePolicyWildcardActionRule import SQSQueuePolicyWildcardActionRule
from cfripper.model.result import Result
from tests.utils import get_cfmodel_from


@pytest.fixture()
def sqs_queue_with_wildcards():
    return get_cfmodel_from("rules/SQSQueuePolicyWildcardActionRule/sqs_queue_with_wildcards.json").resolve()


def test_sqs_queue_with_wildcards(sqs_queue_with_wildcards):
    result = Result()
    rule = SQSQueuePolicyWildcardActionRule(None, result)
    rule.invoke(sqs_queue_with_wildcards)

    assert not result.valid
    assert len(result.failed_rules) == 4
    assert len(result.failed_monitored_rules) == 0
    assert result.failed_rules[0].rule == "SQSQueuePolicyWildcardActionRule"
    assert result.failed_rules[0].reason == "SQS Queue policy mysqspolicy1 should not allow * action"
    assert result.failed_rules[1].rule == "SQSQueuePolicyWildcardActionRule"
    assert result.failed_rules[1].reason == "SQS Queue policy mysqspolicy1b should not allow * action"
    assert result.failed_rules[2].rule == "SQSQueuePolicyWildcardActionRule"
    assert result.failed_rules[2].reason == "SQS Queue policy mysqspolicy1c should not allow * action"
    assert result.failed_rules[3].rule == "SQSQueuePolicyWildcardActionRule"
    assert result.failed_rules[3].reason == "SQS Queue policy mysqspolicy1d should not allow * action"
