from pytest import fixture

from cfripper.config.config import Config
from cfripper.rules import PartialWildcardPrincipalRule
from tests.utils import get_cfmodel_from


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
    assert len(result.failed_rules) == 0
    assert len(result.failed_monitored_rules) == 0


def test_failures_are_raised(bad_template):
    rule = PartialWildcardPrincipalRule(None)
    result = rule.invoke(bad_template)

    assert not result.valid
    assert len(result.failed_rules) == 2
    assert len(result.failed_monitored_rules) == 0
    assert result.failed_rules[0].rule == "PartialWildcardPrincipalRule"
    assert (
        result.failed_rules[0].reason == "PolicyA should not allow wildcard in principals or account-wide principals "
        "(principal: 'arn:aws:iam::123445:12345*')"
    )
    assert result.failed_rules[1].rule == "PartialWildcardPrincipalRule"
    assert (
        result.failed_rules[1].reason == "PolicyA should not allow wildcard in principals or account-wide principals "
        "(principal: 'arn:aws:iam::123445:root')"
    )


def test_failures_for_correct_account_ids(intra_account_root_access):
    rule = PartialWildcardPrincipalRule(Config(aws_account_id="123456789012"))
    result = rule.invoke(intra_account_root_access)

    assert not result.valid
    assert len(result.failed_rules) == 1
    assert len(result.failed_monitored_rules) == 0
    assert result.failed_rules[0].rule == "PartialWildcardPrincipalRule"
    assert (
        result.failed_rules[0].reason
        == "AccLoadBalancerAccessLogBucketPolicy should not allow wildcard in principals or account-wide principals "
        "(principal: 'arn:aws:iam::123456789012:root')"
    )


def test_aws_elb_allow_template(aws_elb_allow_template):
    rule = PartialWildcardPrincipalRule(None)
    result = rule.invoke(aws_elb_allow_template)
    assert result.valid


def test_rule_supports_filter_config(bad_template, default_allow_all_config):
    rule = PartialWildcardPrincipalRule(default_allow_all_config)
    result = rule.invoke(bad_template)
    assert result.valid
