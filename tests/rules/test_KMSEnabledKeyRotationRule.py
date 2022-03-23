import pytest
from pytest import fixture

from cfripper.config.config import Config
from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rules import KMSKeyEnabledKeyRotation
from tests.utils import compare_lists_of_failures, get_cfmodel_from


@fixture()
def bad_template():
    return get_cfmodel_from("rules/KMSEnabledKeyRotation/bad_template_symmetric_no_property.yaml").resolve()


@pytest.mark.parametrize(
    "template_path, success",
    [
        ("rules/KMSEnabledKeyRotation/bad_template_symmetric_keyspec_property.yaml", False),
        ("rules/KMSEnabledKeyRotation/bad_template_symmetric_no_property.yaml", False),
        ("rules/KMSEnabledKeyRotation/bad_template_symmetric_property.yaml", False),
        ("rules/KMSEnabledKeyRotation/good_template.yaml", True),
    ],
)
def test_failures_are_raised(template_path, success):
    rule = KMSKeyEnabledKeyRotation(Config())
    result = rule.invoke(get_cfmodel_from(template_path).resolve())

    if success:
        assert result.valid
        assert compare_lists_of_failures(result.failures, [])
    else:
        assert not result.valid
        assert compare_lists_of_failures(
            result.failures,
            [
                Failure(
                    granularity=RuleGranularity.RESOURCE,
                    reason="KMS Key KMSKey should have the key rotation enabled for symmetric keys",
                    risk_value=RuleRisk.HIGH,
                    rule="KMSKeyEnabledKeyRotation",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids={"KMSKey"},
                    resource_types={"AWS::KMS::Key"},
                )
            ],
        )


def test_rule_supports_filter_config(bad_template, default_allow_all_config):
    rule = KMSKeyEnabledKeyRotation(default_allow_all_config)
    result = rule.invoke(bad_template)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])
