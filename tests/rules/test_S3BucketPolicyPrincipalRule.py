from pytest import fixture

from cfripper.config.config import Config
from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rules import S3BucketPolicyPrincipalRule
from tests.utils import compare_lists_of_failures, get_cfmodel_from


@fixture()
def bad_template():
    return get_cfmodel_from("rules/S3BucketPolicyPrincipalRule/bad_template.json").resolve()


def test_failures_are_raised(bad_template):
    rule = S3BucketPolicyPrincipalRule(Config(aws_principals=["12345"]))
    result = rule.invoke(bad_template)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="S3 Bucket S3BucketPolicy policy has non-allowed principals 1234556",
                risk_value=RuleRisk.HIGH,
                rule="S3BucketPolicyPrincipalRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"S3BucketPolicy"},
                resource_types={"AWS::S3::BucketPolicy"},
            ),
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="S3 Bucket S3BucketPolicy policy has non-allowed principals 1234557",
                risk_value=RuleRisk.HIGH,
                rule="S3BucketPolicyPrincipalRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"S3BucketPolicy"},
                resource_types={"AWS::S3::BucketPolicy"},
            ),
        ],
    )


def test_rule_supports_filter_config(bad_template, default_allow_all_config):
    rule = S3BucketPolicyPrincipalRule(default_allow_all_config)
    result = rule.invoke(bad_template)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])
