import pytest
from pytest import fixture

from cfripper.config.config import Config
from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rules import S3LifecycleConfigurationRule
from tests.utils import compare_lists_of_failures, get_cfmodel_from


@fixture()
def bad_template_no_configuration():
    return get_cfmodel_from("rules/S3LifecycleConfiguration/bad_template_no_configurations.yaml").resolve()


@pytest.mark.parametrize(
    "template_path",
    [
        "rules/S3LifecycleConfiguration/good_template.yaml",
    ],
)
def test_no_failures_are_raised(template_path):
    rule = S3LifecycleConfigurationRule(None)
    result = rule.invoke(get_cfmodel_from(template_path).resolve())

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_failures_are_raised(bad_template_no_configuration):
    rule = S3LifecycleConfigurationRule(Config())
    result = rule.invoke(bad_template_no_configuration)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="S3 Bucket OutputBucket is required to contain a LifecycleConfiguration property",
                risk_value=RuleRisk.LOW,
                rule="S3LifecycleConfigurationRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"OutputBucket"},
                resource_types={"AWS::S3::Bucket"},
            )
        ],
    )


def test_rule_supports_filter_config(bad_template_no_configuration, default_allow_all_config):
    rule = S3LifecycleConfigurationRule(default_allow_all_config)
    result = rule.invoke(bad_template_no_configuration)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])
