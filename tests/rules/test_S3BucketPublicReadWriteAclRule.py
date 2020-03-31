from pytest import fixture

from cfripper.config.config import Config
from cfripper.rules import S3BucketPublicReadWriteAclRule
from tests.utils import get_cfmodel_from


@fixture()
def bad_template():
    return get_cfmodel_from("rules/S3BucketPublicReadWriteAclRule/bad_template.json").resolve()


def test_failures_are_raised(bad_template):
    rule = S3BucketPublicReadWriteAclRule(Config())
    result = rule.invoke(bad_template)

    assert not result.valid
    assert len(result.failed_rules) == 1
    assert len(result.failed_monitored_rules) == 0
    assert result.failed_rules[0].rule == "S3BucketPublicReadWriteAclRule"
    assert result.failed_rules[0].reason == "S3 Bucket S3Bucket should not have a public read-write acl"
