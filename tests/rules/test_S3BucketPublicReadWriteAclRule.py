from pytest import fixture

from cfripper.config.config import Config
from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rules import S3BucketPublicReadWriteAclRule
from tests.utils import compare_lists_of_failures, get_cfmodel_from


@fixture()
def bad_template():
    return get_cfmodel_from("rules/S3BucketPublicReadWriteAclRule/bad_template.json").resolve()


def test_failures_are_raised(bad_template):
    rule = S3BucketPublicReadWriteAclRule(Config())
    result = rule.invoke(bad_template)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="S3 Bucket S3Bucket should not have a public read-write acl",
                risk_value=RuleRisk.HIGH,
                rule="S3BucketPublicReadWriteAclRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"S3Bucket"},
                resource_types={"AWS::S3::Bucket"},
            )
        ],
    )


def test_rule_supports_filter_config(bad_template, default_allow_all_config):
    rule = S3BucketPublicReadWriteAclRule(default_allow_all_config)
    result = rule.invoke(bad_template)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])
