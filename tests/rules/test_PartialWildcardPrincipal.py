from pytest import fixture

from cfripper.config.config import Config
from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rules import PartialWildcardPrincipalRule
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
    rule = PartialWildcardPrincipalRule(None)
    result = rule.invoke(good_template)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_failures_are_raised(bad_template):
    rule = PartialWildcardPrincipalRule(None)
    result = rule.invoke(bad_template)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="PolicyA should not allow wildcard in principals or account-wide principals (principal: 'arn:aws:iam::123445:12345*')",
                risk_value=RuleRisk.MEDIUM,
                rule="PartialWildcardPrincipalRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"PolicyA"},
            ),
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="PolicyA should not allow wildcard in principals or account-wide principals (principal: 'arn:aws:iam::123445:root')",
                risk_value=RuleRisk.MEDIUM,
                rule="PartialWildcardPrincipalRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"PolicyA"},
            ),
        ],
    )


def test_failures_for_correct_account_ids(intra_account_root_access):
    rule = PartialWildcardPrincipalRule(Config(aws_account_id="123456789012"))
    result = rule.invoke(intra_account_root_access)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="AccLoadBalancerAccessLogBucketPolicy should not allow wildcard in principals or account-wide principals (principal: 'arn:aws:iam::123456789012:root')",
                risk_value=RuleRisk.MEDIUM,
                rule="PartialWildcardPrincipalRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"AccLoadBalancerAccessLogBucketPolicy"},
            ),
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="AccLoadBalancerAccessLogBucketPolicy should not allow wildcard in principals or account-wide principals (principal: '987654321012')",
                risk_value=RuleRisk.MEDIUM,
                rule="PartialWildcardPrincipalRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"AccLoadBalancerAccessLogBucketPolicy"},
            ),
        ],
    )


def test_aws_elb_allow_template(aws_elb_allow_template):
    rule = PartialWildcardPrincipalRule(None)
    result = rule.invoke(aws_elb_allow_template)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_rule_supports_filter_config(bad_template, default_allow_all_config):
    rule = PartialWildcardPrincipalRule(default_allow_all_config)
    result = rule.invoke(bad_template)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])
