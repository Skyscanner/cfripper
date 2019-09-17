import pytest
from cfripper.config.config import Config
from cfripper.rules.WildcardPrincipal import GenericWildcardPrincipal


@pytest.fixture
def mock_rule_to_resource_whitelist():
    return {
        "GenericWildcardPrincipal": {
            "test_*": [
                "resource_5",
            ],
            "test_stack": [
                "resource_1",
                "another_resource",
            ],
            "other_stack": [
                "resource_2",
                "another_resource",
            ],
            "stack_without_whitelisted_resources": []
        },
        "OtherRuleThatUsesResourceWhitelists": {
            "test_stack": [
                "resource_3",
            ],
            "other_stack": [
                "resource_4",
            ],
        },
    }


def test_wildcard_principal_rule_is_whitelisted_retrieved_correctly(mock_rule_to_resource_whitelist):
    mock_rules = ["RuleThatUsesResourceWhitelists", "SecurityGroupOpenToWorldRule"]
    config = Config(
        stack_name="test_stack",
        rules=mock_rules,
        stack_whitelist={},
        rule_to_resource_whitelist=mock_rule_to_resource_whitelist

    )

    wildcard_principal_rule = GenericWildcardPrincipal(config=config, result=None)

    assert wildcard_principal_rule.resource_is_whitelisted(logical_id="resource_1") is True
