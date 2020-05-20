import pytest

from cfripper.model.enums import RuleMode
from cfripper.rules.s3_public_access import S3BucketPublicReadAclAndListStatementRule
from tests.utils import get_cfmodel_from


@pytest.fixture()
def s3_read_plus_list():
    return get_cfmodel_from("rules/S3BucketPublicReadAclAndListStatementRule/s3_read_plus_list.json").resolve()


def test_s3_read_plus_list(s3_read_plus_list):
    rule = S3BucketPublicReadAclAndListStatementRule(None)
    result = rule.invoke(s3_read_plus_list)

    assert not result.valid
    assert len(result.failed_rules) == 2
    assert len(result.failed_monitored_rules) == 0
    assert result.failed_rules[0].rule == "S3BucketPublicReadAclAndListStatementRule"
    assert (
        result.failed_rules[0].reason
        == "S3 Bucket S3BucketPolicy should not have a public read acl and list bucket statement"
    )
    assert result.failed_rules[0].rule_mode == RuleMode.BLOCKING
