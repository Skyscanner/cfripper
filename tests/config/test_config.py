import pytest
from pydantic import ValidationError

from cfripper.config.config import Config
from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rule_processor import RuleProcessor
from cfripper.rules import DEFAULT_RULES
from tests.utils import compare_lists_of_failures, get_cfmodel_from


@pytest.fixture()
def template_two_roles_dict():
    return get_cfmodel_from("rules/CrossAccountTrustRule/iam_root_role_cross_account_two_roles.json").resolve()


def test_init_with_no_params():
    config = Config()
    assert config.rules is None
    assert config.aws_account_id is None
    assert config.aws_principals == []
    assert config.metrics_logger is None


def test_init_with_nonexistent_params():
    default_rules = ["IAMRolesOverprivilegedRule", "SecurityGroupOpenToWorldRule"]
    config = Config(project_name="MISSING", service_name="MISSING", stack_name="MISSING", rules=default_rules)

    assert set(config.rules) == set(default_rules)


def test_init_with_existent_params():
    expected_aws_account_id = "123456789012"
    expected_aws_principals = ["234567890123", "345678901234"]

    config = Config(aws_account_id=expected_aws_account_id, aws_principals=expected_aws_principals)

    assert config.aws_account_id == expected_aws_account_id
    assert config.aws_principals == expected_aws_principals


def test_load_rules_config_file_success(test_files_location):
    mock_rules = ["RuleThatUsesResourceAllowlist", "SecurityGroupOpenToWorldRule"]
    config = Config(stack_name="test_stack", rules=mock_rules)
    config.load_rules_config_file(open(f"{test_files_location}/config/rules_config_CrossAccountTrustRule.py"))
    config.add_filters_from_dir(f"{test_files_location}/filters")
    rule_config = config.get_rule_config("CrossAccountTrustRule")
    filters = config.get_rule_filters("CrossAccountTrustRule")
    assert not rule_config.risk_value
    assert not rule_config.rule_mode
    assert len(filters) == 1


def test_load_rules_config_file_no_file(test_files_location):
    mock_rules = ["RuleThatUsesResourceAllowlist", "SecurityGroupOpenToWorldRule"]
    config = Config(stack_name="test_stack", rules=mock_rules)

    with pytest.raises(FileNotFoundError):
        config.load_rules_config_file(open(f"{test_files_location}/config/non_existing_file.py"))


def test_load_rules_config_file_invalid_file(test_files_location):
    mock_rules = ["RuleThatUsesResourceAllowlist", "SecurityGroupOpenToWorldRule"]
    config = Config(stack_name="test_stack", rules=mock_rules)

    with pytest.raises(ValidationError):
        config.load_rules_config_file(open(f"{test_files_location}/config/rules_config_invalid.py"))


def test_load_filters_work_with_several_rules(template_two_roles_dict, test_files_location):
    config = Config(
        rules=["CrossAccountTrustRule", "PartialWildcardPrincipalRule"],
        aws_account_id="123456789",
        stack_name="mockstack",
    )
    config.load_rules_config_file(open(f"{test_files_location}/config/rules_config_CrossAccountTrustRule.py"))
    config.add_filters_from_dir(f"{test_files_location}/filters")
    rules = [DEFAULT_RULES.get(rule)(config) for rule in config.rules]
    processor = RuleProcessor(*rules)
    result = processor.process_cf_template(template_two_roles_dict, config)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="RootRoleTwo has forbidden cross-account trust relationship with arn:aws:iam::999999999:role/someuser@bla.com",
                risk_value=RuleRisk.MEDIUM,
                rule="CrossAccountTrustRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"RootRoleTwo"},
                resource_types={"AWS::IAM::Role"},
            ),
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="RootRoleTwo should not allow wildcard, account-wide or root in resource-id like 'arn:aws:iam::12345:root' at 'arn:aws:iam::123456789:root'",
                risk_value=RuleRisk.MEDIUM,
                rule="PartialWildcardPrincipalRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"RootRoleTwo"},
                resource_types={"AWS::IAM::Role"},
            ),
        ],
    )


def test_load_filters_file_invalid_file(test_files_location):
    mock_rules = ["RuleThatUsesResourceAllowlist", "SecurityGroupOpenToWorldRule"]
    config = Config(stack_name="test_stack", rules=mock_rules)

    with pytest.raises(ValidationError):
        config.add_filters_from_dir(f"{test_files_location}/invalid_filters")
