import pytest

from cfripper.rules import SQSQueuePolicyNotPrincipalRule
from tests.utils import get_cfmodel_from


@pytest.fixture()
def s3_bucket_with_wildcards():
    return get_cfmodel_from("rules/SQSQueuePolicyNotPrincipalRule/bad_template.json").resolve()


def test_s3_bucket_with_wildcards(s3_bucket_with_wildcards):
    rule = SQSQueuePolicyNotPrincipalRule(None)
    result = rule.invoke(s3_bucket_with_wildcards)

    assert result.valid
    assert len(result.failed_rules) == 0
    assert len(result.failed_monitored_rules) == 1
    assert result.failed_monitored_rules[0].rule == "SQSQueuePolicyNotPrincipalRule"
    assert (
        result.failed_monitored_rules[0].reason
        == "SQS Queue QueuePolicyWithNotPrincipal policy should not allow Allow and NotPrincipal at the same time"
    )
