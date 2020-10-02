from pycfmodel.model.cf_model import CFModel
from pytest import fixture

from cfripper.rules import PolicyOnUserRule
from tests.utils import get_cfmodel_from


@fixture()
def good_template():
    return get_cfmodel_from("rules/PolicyOnUserRule/good_template.json").resolve()


@fixture()
def bad_template():
    return get_cfmodel_from("rules/PolicyOnUserRule/bad_template.json").resolve()


def test_no_failures_are_raised(good_template):
    rule = PolicyOnUserRule(None)
    result = rule.invoke(good_template)

    assert result.valid
    assert len(result.failed_rules) == 0
    assert len(result.failed_monitored_rules) == 0


def test_failures_are_raised(bad_template: CFModel):
    rule = PolicyOnUserRule(None)
    result = rule.invoke(bad_template)

    assert not result.valid
    assert len(result.failed_rules) == 1
    assert len(result.failed_monitored_rules) == 0
    assert result.failed_rules[0].rule == "PolicyOnUserRule"
    assert result.failed_rules[0].reason == "IAM policy Policy should not apply directly to users. Should be on group"
