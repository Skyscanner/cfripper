from pytest import fixture

from cfripper.config.config import Config
from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rules import S3CrossAccountTrustRule
from tests.utils import compare_lists_of_failures, get_cfmodel_from


@fixture()
def s3_bucket_cross_account():
    return get_cfmodel_from("rules/S3CrossAccountTrustRule/s3_bucket_cross_account.json").resolve()


@fixture()
def s3_bucket_cross_account_from_aws_service():
    return get_cfmodel_from("rules/S3CrossAccountTrustRule/s3_bucket_cross_account_from_aws_service.json").resolve()


@fixture()
def s3_bucket_cross_account_and_normal():
    return get_cfmodel_from("rules/S3CrossAccountTrustRule/s3_bucket_cross_account_and_normal.json").resolve()


def test_s3_bucket_cross_account(s3_bucket_cross_account):
    rule = S3CrossAccountTrustRule(Config(aws_account_id="123456789"))
    result = rule.invoke(s3_bucket_cross_account)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="S3BucketPolicyAccountAccess has forbidden cross-account policy allow with arn:aws:iam::987654321:root for an S3 bucket.",
                risk_value=RuleRisk.MEDIUM,
                rule="S3CrossAccountTrustRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"S3BucketPolicyAccountAccess"},
                resource_types={"AWS::S3::BucketPolicy"},
            )
        ],
    )


def test_s3_bucket_cross_account_and_normal(s3_bucket_cross_account_and_normal):
    rule = S3CrossAccountTrustRule(Config(aws_account_id="123456789012"))
    result = rule.invoke(s3_bucket_cross_account_and_normal)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="S3BucketPolicyAccountAccess has forbidden cross-account policy allow with arn:aws:iam::666555444333:root for an S3 bucket.",
                risk_value=RuleRisk.MEDIUM,
                rule="S3CrossAccountTrustRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"S3BucketPolicyAccountAccess"},
                resource_types={"AWS::S3::BucketPolicy"},
            )
        ],
    )


def test_s3_bucket_cross_account_and_normal_with_org_aws_account(s3_bucket_cross_account_and_normal):
    rule = S3CrossAccountTrustRule(Config(aws_account_id="123456789012", aws_principals=["666555444333"]))
    result = rule.invoke(s3_bucket_cross_account_and_normal)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="S3BucketPolicyAccountAccess has forbidden cross-account policy allow with arn:aws:iam::666555444333:root for an S3 bucket.",
                risk_value=RuleRisk.MEDIUM,
                rule="S3CrossAccountTrustRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"S3BucketPolicyAccountAccess"},
                resource_types={"AWS::S3::BucketPolicy"},
            )
        ],
    )


def test_s3_bucket_cross_account_for_current_account(s3_bucket_cross_account):
    rule = S3CrossAccountTrustRule(Config(aws_account_id="987654321"))
    result = rule.invoke(s3_bucket_cross_account)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_s3_bucket_cross_account_from_aws_service(s3_bucket_cross_account_from_aws_service):
    rule = S3CrossAccountTrustRule(Config(aws_account_id="123456789"))
    result = rule.invoke(s3_bucket_cross_account_from_aws_service)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_rule_supports_filter_config(s3_bucket_cross_account_and_normal, default_allow_all_config):
    rule = S3CrossAccountTrustRule(default_allow_all_config)
    result = rule.invoke(s3_bucket_cross_account_and_normal)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])
