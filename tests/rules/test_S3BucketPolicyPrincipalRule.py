from pytest import fixture

from cfripper.config.config import Config
from cfripper.rules import S3BucketPolicyPrincipalRule
from tests.utils import get_cfmodel_from


@fixture()
def bad_template():
    return get_cfmodel_from("rules/S3BucketPolicyPrincipalRule/bad_template.json").resolve()


def test_failures_are_raised(bad_template):
    rule = S3BucketPolicyPrincipalRule(Config(aws_principals=["12345"]))
    result = rule.invoke(bad_template)

    assert not result.valid
    assert len(result.failed_rules) == 2
    assert len(result.failed_monitored_rules) == 0
    assert result.failed_rules[0].rule == "S3BucketPolicyPrincipalRule"
    assert result.failed_rules[0].reason == "S3 Bucket S3BucketPolicy policy has non-whitelisted principals 1234556"
    assert result.failed_rules[1].rule == "S3BucketPolicyPrincipalRule"
    assert result.failed_rules[1].reason == "S3 Bucket S3BucketPolicy policy has non-whitelisted principals 1234557"
