import pytest

from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rules.s3_public_access import S3BucketPublicReadAclAndListStatementRule
from tests.utils import compare_lists_of_failures, get_cfmodel_from


@pytest.fixture()
def s3_read_plus_list():
    return get_cfmodel_from("rules/S3BucketPublicReadAclAndListStatementRule/s3_read_plus_list.json").resolve()


def test_s3_read_plus_list(s3_read_plus_list):
    rule = S3BucketPublicReadAclAndListStatementRule(None)
    result = rule.invoke(s3_read_plus_list)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="S3 Bucket S3BucketPolicy should not have a public read acl and list bucket statement",
                risk_value=RuleRisk.MEDIUM,
                rule="S3BucketPublicReadAclAndListStatementRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"S3BucketPolicy"},
            ),
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="S3 Bucket S3BucketPolicy2 should not have a public read acl and list bucket statement",
                risk_value=RuleRisk.MEDIUM,
                rule="S3BucketPublicReadAclAndListStatementRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"S3BucketPolicy2"},
            ),
        ],
    )


def test_rule_supports_filter_config(s3_read_plus_list, default_allow_all_config):
    rule = S3BucketPublicReadAclAndListStatementRule(default_allow_all_config)
    result = rule.invoke(s3_read_plus_list)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])
