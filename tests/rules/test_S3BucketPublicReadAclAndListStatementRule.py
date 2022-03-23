from unittest.mock import MagicMock, patch

import pytest

from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rules.s3_public_access import S3BucketPublicReadAclAndListStatementRule
from tests.utils import compare_lists_of_failures, get_cfmodel_from


def get_s3_read_plus_list():
    return get_cfmodel_from("rules/S3BucketPublicReadAclAndListStatementRule/s3_read_plus_list.json")


@pytest.fixture()
def unresolved_s3_read_plus_list():
    return get_s3_read_plus_list()


@pytest.fixture()
def s3_read_plus_list():
    return get_s3_read_plus_list().resolve()


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
                resource_types={"AWS::S3::BucketPolicy"},
            ),
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="S3 Bucket S3BucketPolicy2 should not have a public read acl and list bucket statement",
                risk_value=RuleRisk.MEDIUM,
                rule="S3BucketPublicReadAclAndListStatementRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"S3BucketPolicy2"},
                resource_types={"AWS::S3::BucketPolicy"},
            ),
        ],
    )


@patch("cfripper.rules.s3_public_access.logger")
def test_s3_read_plus_list_with_unresolved_template(patched_logger: MagicMock, unresolved_s3_read_plus_list):
    rule = S3BucketPublicReadAclAndListStatementRule(None)

    try:
        rule.invoke(unresolved_s3_read_plus_list)
        assert patched_logger.warning.call_count == 2
    except TypeError:
        assert False, "S3BucketPublicReadAclAndListStatementRule crashed"


def test_rule_supports_filter_config(s3_read_plus_list, default_allow_all_config):
    rule = S3BucketPublicReadAclAndListStatementRule(default_allow_all_config)
    result = rule.invoke(s3_read_plus_list)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])
