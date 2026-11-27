import pytest

from cfripper.config.config import Config
from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rules import DEFAULT_RULES, RDSInstancePubliclyAccessibleRule
from tests.utils import compare_lists_of_failures, get_cfmodel_from


def test_rule_is_a_default_rule():
    assert DEFAULT_RULES["RDSInstancePubliclyAccessibleRule"] is RDSInstancePubliclyAccessibleRule


def test_rule_passing():
    rule = RDSInstancePubliclyAccessibleRule(None)
    result = rule.invoke(get_cfmodel_from("rules/RDSInstancePubliclyAccessible/good_template.yaml").resolve())

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


@pytest.mark.parametrize(
    "template_path, resource_type",
    [
        ("rules/RDSInstancePubliclyAccessible/public_instance.yaml", "AWS::RDS::DBInstance"),
        ("rules/RDSInstancePubliclyAccessible/public_instance_string_value.yaml", "AWS::RDS::DBInstance"),
        ("rules/RDSInstancePubliclyAccessible/public_instance_padded_string_value.yaml", "AWS::RDS::DBInstance"),
    ],
)
def test_failures_are_raised(template_path, resource_type):
    rule = RDSInstancePubliclyAccessibleRule(Config())
    result = rule.invoke(get_cfmodel_from(template_path).resolve())

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="RDS instance PublicDatabase should not be publicly accessible, set PubliclyAccessible to false",
                risk_value=RuleRisk.HIGH,
                rule="RDSInstancePubliclyAccessibleRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"PublicDatabase"},
                resource_types={resource_type},
            )
        ],
    )
