import pytest

from cfripper.config.config import Config
from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rules.wildcard_principals import GenericWildcardPrincipalRule
from tests.utils import compare_lists_of_failures, get_cfmodel_from


@pytest.fixture()
def good_template():
    return get_cfmodel_from("rules/GenericWildcardPrincipalRule/good_template.json").resolve()


@pytest.fixture()
def bad_template():
    return get_cfmodel_from("rules/GenericWildcardPrincipalRule/bad_template.json").resolve()


def test_no_failures_are_raised(good_template):
    rule = GenericWildcardPrincipalRule(None)
    result = rule.invoke(good_template)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_failures_are_raised(bad_template):
    rule = GenericWildcardPrincipalRule(None)
    result = rule.invoke(bad_template)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="PolicyA should not allow wildcards in principals (principal: 'somewhatrestricted:*')",
                risk_value=RuleRisk.MEDIUM,
                rule="GenericWildcardPrincipalRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"PolicyA"},
            ),
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="PolicyA should not allow wildcards in principals (principal: 'arn:aws:iam::123445:*')",
                risk_value=RuleRisk.MEDIUM,
                rule="GenericWildcardPrincipalRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"PolicyA"},
            ),
        ],
    )


def test_generic_wildcard_ignores_kms():
    rule = GenericWildcardPrincipalRule(Config(aws_account_id="123456789", aws_principals=["999999999"]))
    model = get_cfmodel_from("rules/CrossAccountTrustRule/kms_basic.yml").resolve(
        extra_params={"Principal": "arn:aws:iam::*:*"}
    )
    result = rule.invoke(model)
    assert result.valid
    assert compare_lists_of_failures(result.failures, [])
