import pytest

from cfripper.config.config import Config
from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rules import S3ObjectVersioningRule
from tests.utils import compare_lists_of_failures, get_cfmodel_from


def test_rule_passing():
    template_path = "rules/S3ObjectVersioning/good_template.yaml"
    rule = S3ObjectVersioningRule(None)
    result = rule.invoke(get_cfmodel_from(template_path).resolve())

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


@pytest.mark.parametrize(
    "template_path",
    ["rules/S3ObjectVersioning/status_suspended.yaml", "rules/S3ObjectVersioning/no_versioning_defined.yaml"],
)
def test_failures_are_raised(template_path):
    rule = S3ObjectVersioningRule(Config())
    result = rule.invoke(get_cfmodel_from(template_path).resolve())

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="S3 Bucket VersionBucket is required to have object versioning enabled",
                risk_value=RuleRisk.LOW,
                rule="S3ObjectVersioningRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"VersionBucket"},
                resource_types={"AWS::S3::Bucket"},
            )
        ],
    )
