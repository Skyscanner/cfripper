import pytest

from cfripper.config.config import Config
from cfripper.rules.ebs_volume_has_sse import EBSVolumeHasSSERule
from tests.utils import get_cfmodel_from


@pytest.fixture()
def good_template():
    return get_cfmodel_from("rules/EBSVolumeHasSSERule/good_template.json").resolve()


@pytest.fixture()
def bad_template():
    return get_cfmodel_from("rules/EBSVolumeHasSSERule/bad_template.json").resolve()


def test_no_failures_are_raised(good_template):
    rule = EBSVolumeHasSSERule(Config(aws_account_id="123456789"))
    result = rule.invoke(good_template)

    assert result.valid
    assert len(result.failed_rules) == 0
    assert len(result.failed_monitored_rules) == 0


def test_failures_are_raised(bad_template):
    rule = EBSVolumeHasSSERule(Config(aws_account_id="123456789"))
    result = rule.invoke(bad_template)

    assert not result.valid
    assert len(result.failed_rules) == 1
    assert len(result.failed_monitored_rules) == 0
    assert result.failed_rules[0].rule == "EBSVolumeHasSSERule"
    assert result.failed_rules[0].reason == "EBS volume TestVolume should have server-side encryption enabled"
