import pytest

from cfripper.config.config import Config
from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rules.ebs_volume_has_sse import EBSVolumeHasSSERule
from tests.utils import compare_lists_of_failures, get_cfmodel_from


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
    assert compare_lists_of_failures(result.failures, [])


@pytest.mark.parametrize(
    "template_path",
    ["rules/EBSVolumeHasSSERule/bad_template.json", "rules/EBSVolumeHasSSERule/bad_template.yaml"],
)
def test_failures_are_raised(template_path):
    rule = EBSVolumeHasSSERule(Config(aws_account_id="123456789"))
    result = rule.invoke(get_cfmodel_from(template_path).resolve())

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="EBS volume TestVolume should have server-side encryption enabled",
                risk_value=RuleRisk.MEDIUM,
                rule="EBSVolumeHasSSERule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"TestVolume"},
                resource_types={"AWS::EC2::Volume"},
            )
        ],
    )


def test_rule_supports_filter_config(bad_template, default_allow_all_config):
    rule = EBSVolumeHasSSERule(default_allow_all_config)
    result = rule.invoke(bad_template)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])
