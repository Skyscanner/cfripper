from pytest import fixture

from cfripper.rules import PartialWildcardPrincipalRule
from tests.utils import get_cfmodel_from


@fixture()
def good_template():
    return get_cfmodel_from("rules/PartialWildcardPrincipalRule/good_template.json").resolve()


@fixture()
def bad_template():
    return get_cfmodel_from("rules/PartialWildcardPrincipalRule/bad_template.json").resolve()


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
    assert len(result.failed_rules) == 4
    assert len(result.failed_monitored_rules) == 0
    assert result.failed_rules[0].rule == "PartialWildcardPrincipalRule"
    assert result.failed_rules[0].reason == "PolicyA contains an unknown principal: 123445"
    assert result.failed_rules[1].rule == "PartialWildcardPrincipalRule"
    assert (
        result.failed_rules[1].reason == "PolicyA should not allow wildcard in principals or account-wide principals "
        "(principal: 'arn:aws:iam::123445:12345*')"
    )
    assert result.failed_rules[2].rule == "PartialWildcardPrincipalRule"
    assert result.failed_rules[2].reason == "PolicyA contains an unknown principal: 123445"
    assert result.failed_rules[3].rule == "PartialWildcardPrincipalRule"
    assert (
        result.failed_rules[3].reason == "PolicyA should not allow wildcard in principals or account-wide principals "
        "(principal: 'arn:aws:iam::123445:root')"
    )
