from pytest import fixture

from cfripper.config.config import Config
from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rules import GenericResourcePartialWildcardPrincipalRule
from tests.utils import compare_lists_of_failures, get_cfmodel_from


@fixture()
def good_template():
    return get_cfmodel_from("rules/PartialWildcardPrincipalRule/good_template.json").resolve()


@fixture()
def bad_template():
    return get_cfmodel_from("rules/PartialWildcardPrincipalRule/bad_template.json").resolve()


@fixture()
def intra_account_root_access():
    return get_cfmodel_from("rules/PartialWildcardPrincipalRule/intra_account_root_access.yml").resolve()


@fixture()
def aws_elb_allow_template():
    return get_cfmodel_from("rules/PartialWildcardPrincipalRule/aws_elb_template.yml").resolve(
        extra_params={"AWS::Region": "ap-southeast-1"}
    )


def test_no_failures_are_raised(good_template):
    rule = GenericResourcePartialWildcardPrincipalRule(None)
    result = rule.invoke(good_template)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_failures_are_raised(bad_template):
    rule = GenericResourcePartialWildcardPrincipalRule(None)
    result = rule.invoke(bad_template)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="PolicyA should not allow wildcard, account-wide or root in resource-id like `arn:aws:iam::12345:root` at `arn:aws:iam::123445:12345*`",
                risk_value=RuleRisk.MEDIUM,
                rule="GenericResourcePartialWildcardPrincipalRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"PolicyA"},
                resource_types={"AWS::IAM::Policy"},
            ),
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="PolicyA should not allow wildcard, account-wide or root in resource-id like `arn:aws:iam::12345:root` at `arn:aws:iam::123445:root`",
                risk_value=RuleRisk.MEDIUM,
                rule="GenericResourcePartialWildcardPrincipalRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"PolicyA"},
                resource_types={"AWS::IAM::Policy"},
            ),
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="PolicyA should not allow wildcard, account-wide or root in resource-id like `arn:aws:iam::12345:root` at `79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be`",
                risk_value=RuleRisk.MEDIUM,
                rule="GenericResourcePartialWildcardPrincipalRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"PolicyA"},
                resource_types={"AWS::IAM::Policy"},
            ),
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="PolicyA should not allow wildcard, account-wide or root in resource-id like `arn:aws:iam::12345:root` at `eb2fe74dc7e8125d8f8fcae89d90e6dfdecabf896e1a69d55e949b009fd95a97`",
                risk_value=RuleRisk.MEDIUM,
                rule="GenericResourcePartialWildcardPrincipalRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"PolicyA"},
                resource_types={"AWS::IAM::Policy"},
            ),
        ],
    )


def test_failures_for_correct_account_ids(intra_account_root_access):
    rule = GenericResourcePartialWildcardPrincipalRule(Config(aws_account_id="123456789012"))
    result = rule.invoke(intra_account_root_access)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="AccLoadBalancerAccessLogBucketPolicy should not allow wildcard, account-wide or root in resource-id like `arn:aws:iam::12345:root` at `arn:aws:iam::123456789012:root`",
                risk_value=RuleRisk.MEDIUM,
                rule="GenericResourcePartialWildcardPrincipalRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"AccLoadBalancerAccessLogBucketPolicy"},
                resource_types={"AWS::S3::BucketPolicy"},
            ),
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="AccLoadBalancerAccessLogBucketPolicy should not allow wildcard, account-wide or root in resource-id like `arn:aws:iam::12345:root` at `987654321012`",
                risk_value=RuleRisk.MEDIUM,
                rule="GenericResourcePartialWildcardPrincipalRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"AccLoadBalancerAccessLogBucketPolicy"},
                resource_types={"AWS::S3::BucketPolicy"},
            ),
        ],
    )


def test_aws_elb_allow_template(aws_elb_allow_template):
    rule = GenericResourcePartialWildcardPrincipalRule(None)
    result = rule.invoke(aws_elb_allow_template)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_rule_supports_filter_config(bad_template, default_allow_all_config):
    rule = GenericResourcePartialWildcardPrincipalRule(default_allow_all_config)
    result = rule.invoke(bad_template)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])
