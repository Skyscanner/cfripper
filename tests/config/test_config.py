import pytest

from cfripper.config.config import Config


def test_init_with_no_params():
    config = Config()
    assert config.rules is None


def test_init_with_nonexistent_params():
    default_rules = ["IAMRolesOverprivilegedRule", "SecurityGroupOpenToWorldRule"]
    config = Config(project_name="MISSING", service_name="MISSING", stack_name="MISSING", rules=default_rules)

    assert set(config.rules) == set(default_rules)


def test_with_exemption():
    whitelist = {r"not_.*": ["IAMRolesOverprivilegedRule"], r"test_.*": ["IAMRolesOverprivilegedRule"]}

    default_rules = ["IAMRolesOverprivilegedRule", "SecurityGroupOpenToWorldRule"]
    cfg = Config(stack_name="test_stack", rules=default_rules, stack_whitelist=whitelist)

    assert set(cfg.rules) != set(default_rules)


def test_with_non_existing_exemption():
    whitelist = {"test_project": {"test_service": {"test_stack": ["MISSING"]}}}

    default_rules = ["IAMRolesOverprivilegedRule", "SecurityGroupOpenToWorldRule"]
    cfg = Config(
        project_name="test_project",
        service_name="test_service",
        stack_name="test_stack",
        rules=default_rules,
        stack_whitelist=whitelist,
    )

    assert set(cfg.rules) == set(default_rules)


@pytest.fixture
def mock_rule_to_resource_whitelist():
    return {
        "RuleThatUsesResourceWhitelists": {
            "test_*": ["resource_5"],
            "test_stack": ["resource_1", "another_resource"],
            "other_stack": ["resource_2", "another_resource"],
            "stack_without_whitelisted_resources": [],
        },
        "OtherRuleThatUsesResourceWhitelists": {"test_stack": ["resource_3"], "other_stack": ["resource_4"]},
    }


def test_stack_to_resource_whitelist_normal_behavior(mock_rule_to_resource_whitelist):
    mock_rules = ["RuleThatUsesResourceWhitelists", "SecurityGroupOpenToWorldRule"]
    config = Config(
        stack_name="test_stack",
        rules=mock_rules,
        stack_whitelist={},
        rule_to_resource_whitelist=mock_rule_to_resource_whitelist,
    )
    assert config.get_whitelisted_resources("RuleThatUsesResourceWhitelists") == [
        "resource_5",
        "resource_1",
        "another_resource",
    ]


def test_stack_to_resource_whitelist_rule_not_in_whitelist(mock_rule_to_resource_whitelist):
    mock_rules = ["RuleThatUsesResourceWhitelists", "SecurityGroupOpenToWorldRule"]
    config = Config(
        stack_name="test_stack",
        rules=mock_rules,
        stack_whitelist={},
        rule_to_resource_whitelist=mock_rule_to_resource_whitelist,
    )
    assert config.get_whitelisted_resources("SecurityGroupOpenToWorldRule") == []


def test_stack_to_resource_whitelist_stack_not_in_whitelist(mock_rule_to_resource_whitelist):
    mock_rules = ["RuleThatUsesResourceWhitelists", "SecurityGroupOpenToWorldRule"]
    config = Config(
        stack_name="stack_without_whitelisted_resources",
        rules=mock_rules,
        stack_whitelist={},
        rule_to_resource_whitelist=mock_rule_to_resource_whitelist,
    )
    assert config.get_whitelisted_resources("SecurityGroupOpenToWorldRule") == []


def test_stack_to_resource_whitelist_stack_without_resources(mock_rule_to_resource_whitelist):
    mock_rules = ["RuleThatUsesResourceWhitelists", "SecurityGroupOpenToWorldRule"]
    config = Config(
        stack_name="test_stack_not_whitelisted",
        rules=mock_rules,
        stack_whitelist={},
        rule_to_resource_whitelist=mock_rule_to_resource_whitelist,
    )
    assert config.get_whitelisted_resources("SecurityGroupOpenToWorldRule") == []


@pytest.fixture
def mock_rule_to_action_whitelist():
    return {
        "RuleThatUsesActionWhitelists": {
            "stack_*": ["s3:GetItem"],
            "stack_2": ["kms:*", "dynamodb:CreateTable"],
            "other_stack": ["s3:GetItem"],
            "stack_without_whitelisted_resources": [],
        },
        "OtherRuleThatUsesResourceWhitelists": {"test_stack": [], "other_stack": [".*"]},
    }


def test_stack_to_action_whitelist_normal_behavior(mock_rule_to_action_whitelist):
    mock_rules = ["RuleThatUsesResourceWhitelists", "SecurityGroupOpenToWorldRule"]
    config = Config(
        stack_name="stack_2",
        rules=mock_rules,
        stack_whitelist={},
        rule_to_action_whitelist=mock_rule_to_action_whitelist,
    )
    assert config.get_whitelisted_actions("RuleThatUsesActionWhitelists") == [
        "s3:GetItem",
        "kms:*",
        "dynamodb:CreateTable",
    ]


def test_stack_to_action_whitelist_rule_not_in_whitelist(mock_rule_to_action_whitelist):
    mock_rules = ["RuleThatUsesResourceWhitelists", "SecurityGroupOpenToWorldRule"]
    config = Config(
        stack_name="test_stack",
        rules=mock_rules,
        stack_whitelist={},
        rule_to_action_whitelist=mock_rule_to_action_whitelist,
    )
    assert config.get_whitelisted_actions("SecurityGroupOpenToWorldRule") == []


def test_stack_to_action_whitelist_stack_not_in_whitelist(mock_rule_to_action_whitelist):
    mock_rules = ["RuleThatUsesResourceWhitelists", "SecurityGroupOpenToWorldRule"]
    config = Config(
        stack_name="test_stack_not_whitelisted",
        rules=mock_rules,
        stack_whitelist={},
        rule_to_action_whitelist=mock_rule_to_action_whitelist,
    )
    assert config.get_whitelisted_actions("SecurityGroupOpenToWorldRule") == []


def test_stack_to_action_whitelist_stack_without_resources(mock_rule_to_action_whitelist):
    mock_rules = ["RuleThatUsesResourceWhitelists", "SecurityGroupOpenToWorldRule"]
    config = Config(
        stack_name="stack_without_whitelisted_resources",
        rules=mock_rules,
        stack_whitelist={},
        rule_to_action_whitelist=mock_rule_to_action_whitelist,
    )
    assert config.get_whitelisted_actions("SecurityGroupOpenToWorldRule") == []
