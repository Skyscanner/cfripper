import pytest

from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rules.wildcard_policies import GenericResourceWildcardPolicyRule
from tests.utils import compare_lists_of_failures, get_cfmodel_from


def s3_bucket_with_wildcards():
    return get_cfmodel_from("rules/WildcardPoliciesRule/s3_bucket_with_wildcards.json").resolve()


def sqs_queue_with_wildcards():
    return get_cfmodel_from("rules/WildcardPoliciesRule/sqs_queue_with_wildcards.json").resolve()


def sns_topic_with_wildcards():
    return get_cfmodel_from("rules/WildcardPoliciesRule/sns_topic_with_wildcards.json").resolve()


def generic_with_wildcards():
    return get_cfmodel_from("rules/WildcardPoliciesRule/generic_with_wildcards.json").resolve()


@pytest.fixture()
def sns_topic_with_wildcards_fixture():
    return sns_topic_with_wildcards()


@pytest.mark.parametrize(
    "template, is_valid, failures",
    [
        (
            sns_topic_with_wildcards(),
            False,
            [
                Failure(
                    granularity=RuleGranularity.RESOURCE,
                    reason="mysnspolicy1 should not allow a `*` action",
                    risk_value=RuleRisk.MEDIUM,
                    rule="GenericResourceWildcardPolicyRule",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids={"mysnspolicy1"},
                )
            ],
        ),
        (
            sqs_queue_with_wildcards(),
            False,
            [
                Failure(
                    granularity=RuleGranularity.RESOURCE,
                    reason="mysqspolicy1 should not allow a `*` action",
                    risk_value=RuleRisk.MEDIUM,
                    rule="GenericResourceWildcardPolicyRule",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids={"mysqspolicy1"},
                ),
                Failure(
                    granularity=RuleGranularity.RESOURCE,
                    reason="mysqspolicy1b should not allow a `*` action",
                    risk_value=RuleRisk.MEDIUM,
                    rule="GenericResourceWildcardPolicyRule",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids={"mysqspolicy1b"},
                ),
                Failure(
                    granularity=RuleGranularity.RESOURCE,
                    reason="mysqspolicy1c should not allow a `*` action",
                    risk_value=RuleRisk.MEDIUM,
                    rule="GenericResourceWildcardPolicyRule",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids={"mysqspolicy1c"},
                ),
                Failure(
                    granularity=RuleGranularity.RESOURCE,
                    reason="mysqspolicy1d should not allow a `*` action",
                    risk_value=RuleRisk.MEDIUM,
                    rule="GenericResourceWildcardPolicyRule",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids={"mysqspolicy1d"},
                ),
            ],
        ),
        (
            s3_bucket_with_wildcards(),
            False,
            [
                Failure(
                    granularity=RuleGranularity.RESOURCE,
                    reason="S3BucketPolicy should not allow a `*` action",
                    risk_value=RuleRisk.MEDIUM,
                    rule="GenericResourceWildcardPolicyRule",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids={"S3BucketPolicy"},
                ),
                Failure(
                    granularity=RuleGranularity.RESOURCE,
                    reason="S3BucketPolicy2 should not allow a `*` action",
                    risk_value=RuleRisk.MEDIUM,
                    rule="GenericResourceWildcardPolicyRule",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids={"S3BucketPolicy2"},
                ),
            ],
        ),
        (
            generic_with_wildcards(),
            False,
            [
                Failure(
                    granularity=RuleGranularity.RESOURCE,
                    reason="NotMapped4 should not allow a `*` action",
                    risk_value=RuleRisk.MEDIUM,
                    rule="GenericResourceWildcardPolicyRule",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids={"NotMapped4"},
                ),
                Failure(
                    granularity=RuleGranularity.RESOURCE,
                    reason="NotMapped5 should not allow a `*` action",
                    risk_value=RuleRisk.MEDIUM,
                    rule="GenericResourceWildcardPolicyRule",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids={"NotMapped5"},
                ),
            ],
        ),
    ],
)
def test_generic_rule_with_already_mapped_resources(template, is_valid, failures):
    rule = GenericResourceWildcardPolicyRule(None)
    result = rule.invoke(template)
    assert result.valid == is_valid
    assert compare_lists_of_failures(result.failures, failures,)


def test_rule_supports_filter_config(sns_topic_with_wildcards_fixture, default_allow_all_config):
    rule = GenericResourceWildcardPolicyRule(default_allow_all_config)
    result = rule.invoke(sns_topic_with_wildcards_fixture)
    assert result.valid
    assert compare_lists_of_failures(result.failures, [])
