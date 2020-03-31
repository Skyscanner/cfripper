import pytest

from cfripper.rules import FullWildcardPrincipalRule
from tests.utils import get_cfmodel_from


@pytest.fixture()
def good_template():
    return get_cfmodel_from("rules/FullWilcardPrincipalRule/good_template.json").resolve()


@pytest.fixture()
def bad_template():
    return get_cfmodel_from("rules/FullWilcardPrincipalRule/bad_template.json").resolve()


def test_no_failures_are_raised(good_template):
    rule = FullWildcardPrincipalRule(None)
    result = rule.invoke(good_template)

    assert result.valid
    assert len(result.failed_rules) == 0
    assert len(result.failed_monitored_rules) == 0


def test_failures_are_raised(bad_template):
    rule = FullWildcardPrincipalRule(None)
    result = rule.invoke(bad_template)

    assert not result.valid
    assert len(result.failed_rules) == 1
    assert len(result.failed_monitored_rules) == 0
    assert result.failed_rules[0].rule == "FullWildcardPrincipalRule"
    assert result.failed_rules[0].reason == "PolicyA should not allow wildcards in principals (principal: '*')"
