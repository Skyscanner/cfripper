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

from cfripper.model.enums import RuleRisk
from cfripper.model.result import Result
from cfripper.rules import SQSQueuePolicyPublicRule
from tests.utils import get_cfmodel_from


@pytest.fixture()
def sqs_policy_public():
    return get_cfmodel_from("rules/SQSQueuePolicyPublicRule/sqs_policy_public.json").resolve()


def test_sqs_policy_public(sqs_policy_public):
    result = Result()
    rule = SQSQueuePolicyPublicRule(None, result)
    rule.invoke(sqs_policy_public)

    assert not result.valid
    assert len(result.failed_rules) == 4
    assert len(result.failed_monitored_rules) == 0
    assert result.failed_rules[0].risk_value == RuleRisk.HIGH
    assert result.failed_rules[0].rule == "SQSQueuePolicyPublicRule"
    assert result.failed_rules[0].reason == "SQS Queue policy QueuePolicyPublic1 should not be public"
    assert result.failed_rules[1].rule == "SQSQueuePolicyPublicRule"
    assert result.failed_rules[1].reason == "SQS Queue policy QueuePolicyPublic2 should not be public"
    assert result.failed_rules[2].rule == "SQSQueuePolicyPublicRule"
    assert result.failed_rules[2].reason == "SQS Queue policy QueuePolicyPublic3 should not be public"
    assert result.failed_rules[3].rule == "SQSQueuePolicyPublicRule"
    assert result.failed_rules[3].reason == "SQS Queue policy QueuePolicyPublic4 should not be public"
