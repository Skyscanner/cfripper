import pytest

from cfripper.config.config import Config
from cfripper.rules.wildcard_principals import GenericWildcardPrincipalRule
from tests.utils import get_cfmodel_from


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
    assert len(result.failed_rules) == 0
    assert len(result.failed_monitored_rules) == 0


def test_failures_are_raised(bad_template):
    rule = GenericWildcardPrincipalRule(None)
    result = rule.invoke(bad_template)

    assert not result.valid
    assert len(result.failed_rules) == 3
    assert len(result.failed_monitored_rules) == 0
    assert result.failed_rules[0].rule == "GenericWildcardPrincipalRule"
    assert (
        result.failed_rules[0].reason == "PolicyA should not allow wildcard in principals or account-wide principals "
        "(principal: 'somewhatrestricted:*')"
    )
    assert result.failed_rules[1].rule == "GenericWildcardPrincipalRule"
    assert result.failed_rules[1].reason == "PolicyA contains an unknown principal: 123445"
    assert result.failed_rules[2].rule == "GenericWildcardPrincipalRule"
    assert (
        result.failed_rules[2].reason == "PolicyA should not allow wildcard in principals or account-wide principals "
        "(principal: 'arn:aws:iam::123445:*')"
    )


@pytest.fixture
def mock_rule_to_resource_whitelist():
    return {
        "GenericWildcardPrincipalRule": {
            "test_*": ["resource_5"],
            "test_stack": ["resource_1", "another_resource"],
            "other_stack": ["resource_2", "another_resource"],
            "stack_without_whitelisted_resources": [],
        },
        "OtherRuleThatUsesResourceWhitelists": {"test_stack": ["resource_3"], "other_stack": ["resource_4"]},
    }


def test_wildcard_principal_rule_is_whitelisted_retrieved_correctly(mock_rule_to_resource_whitelist):
    mock_rules = ["RuleThatUsesResourceWhitelists", "SecurityGroupOpenToWorldRule"]
    config = Config(
        stack_name="test_stack",
        rules=mock_rules,
        stack_whitelist={},
        rule_to_resource_whitelist=mock_rule_to_resource_whitelist,
    )

    wildcard_principal_rule = GenericWildcardPrincipalRule(config=config)

    assert wildcard_principal_rule.resource_is_whitelisted(logical_id="resource_1") is True


def test_generic_wildcard_ignores_kms():
    rule = GenericWildcardPrincipalRule(Config(aws_account_id="123456789", aws_principals=["999999999"]))
    model = get_cfmodel_from("rules/CrossAccountTrustRule/kms_basic.yml").resolve(
        extra_params={"Principal": "arn:aws:iam::*:*"}
    )
    result = rule.invoke(model)
    assert result.valid
