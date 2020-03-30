import pytest

from cfripper.config.config import Config
from cfripper.config.filter import Filter
from cfripper.config.rule_config import RuleConfig
from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rule_processor import RuleProcessor
from cfripper.rules import DEFAULT_RULES, KMSKeyCrossAccountTrustRule
from cfripper.rules.cross_account_trust import CrossAccountTrustRule
from tests.utils import get_cfmodel_from


@pytest.fixture()
def template_one_role():
    return get_cfmodel_from("rules/CrossAccountTrustRule/iam_root_role_cross_account.json").resolve()


@pytest.fixture()
def template_two_roles_dict():
    return get_cfmodel_from("rules/CrossAccountTrustRule/iam_root_role_cross_account_two_roles.json").resolve()


@pytest.fixture()
def template_valid_with_service():
    return get_cfmodel_from("rules/CrossAccountTrustRule/valid_with_service.json").resolve()


@pytest.fixture()
def template_valid_with_canonical_id():
    return get_cfmodel_from("rules/CrossAccountTrustRule/valid_with_canonical_id.json").resolve()


@pytest.fixture()
def template_valid_with_sts():
    return get_cfmodel_from("rules/CrossAccountTrustRule/valid_with_sts.yml").resolve()


@pytest.fixture()
def template_invalid_with_sts():
    return get_cfmodel_from("rules/CrossAccountTrustRule/invalid_with_sts.yml").resolve()


@pytest.fixture()
def expected_result_two_roles():
    return [
        Failure(
            rule="CrossAccountTrustRule",
            reason=(
                "RootRoleOne has forbidden cross-account trust relationship with "
                "arn:aws:iam::999999999:role/someuser@bla.com"
            ),
            rule_mode=RuleMode.BLOCKING,
            risk_value=RuleRisk.MEDIUM,
            resource_ids={"RootRoleOne"},
            actions=set(),
            granularity=RuleGranularity.RESOURCE,
        ),
        Failure(
            rule="CrossAccountTrustRule",
            reason=(
                "RootRoleTwo has forbidden cross-account trust relationship with "
                "arn:aws:iam::999999999:role/someuser@bla.com"
            ),
            rule_mode=RuleMode.BLOCKING,
            risk_value=RuleRisk.MEDIUM,
            resource_ids={"RootRoleTwo"},
            actions=set(),
            granularity=RuleGranularity.RESOURCE,
        ),
    ]


def test_report_format_is_the_one_expected(template_one_role):
    rule = CrossAccountTrustRule(Config(aws_account_id="123456789"))
    result = rule.invoke(template_one_role)

    assert not result.valid
    assert result.failed_rules == [
        Failure(
            rule="CrossAccountTrustRule",
            reason=(
                "RootRole has forbidden cross-account trust relationship with arn:aws:iam::999999999:role/"
                "someuser@bla.com"
            ),
            rule_mode=RuleMode.BLOCKING,
            risk_value=RuleRisk.MEDIUM,
            resource_ids={"RootRole"},
            actions=set(),
            granularity=RuleGranularity.RESOURCE,
        ),
    ]


def test_resource_whitelisting_works_as_expected(template_two_roles_dict, expected_result_two_roles):
    mock_rule_to_resource_whitelist = {"CrossAccountTrustRule": {".*": {"RootRoleOne"}}}
    mock_config = Config(
        rules=["CrossAccountTrustRule"],
        aws_account_id="123456789",
        rule_to_resource_whitelist=mock_rule_to_resource_whitelist,
        stack_name="mockstack",
        stack_whitelist={},
    )
    rules = [DEFAULT_RULES.get(rule)(mock_config) for rule in mock_config.rules]
    processor = RuleProcessor(*rules)
    result = processor.process_cf_template(template_two_roles_dict, mock_config)

    assert not result.valid
    assert result.failed_rules[0] == expected_result_two_roles[-1]


def test_filter_works_as_expected(template_two_roles_dict, expected_result_two_roles):
    config = Config(
        rules=["CrossAccountTrustRule"],
        aws_account_id="123456789",
        stack_name="mockstack",
        rules_config={
            "CrossAccountTrustRule": RuleConfig(
                filters=[
                    Filter(
                        rule_mode=RuleMode.WHITELISTED,
                        eval={
                            "and": [
                                {"eq": [{"ref": "config.stack_name"}, "mockstack"]},
                                {"eq": [{"ref": "logical_id"}, "RootRoleOne"]},
                            ]
                        },
                    )
                ],
            )
        },
    )
    rules = [DEFAULT_RULES.get(rule)(config) for rule in config.rules]
    processor = RuleProcessor(*rules)
    result = processor.process_cf_template(template_two_roles_dict, config)

    assert not result.valid
    assert result.failed_rules[0] == expected_result_two_roles[-1]


def test_whitelisted_stacks_do_not_report_anything(template_two_roles_dict):
    mock_stack_whitelist = {"mockstack": ["CrossAccountTrustRule"]}
    mock_config = Config(
        rules=["CrossAccountTrustRule"],
        aws_account_id="123456789",
        stack_name="mockstack",
        stack_whitelist=mock_stack_whitelist,
    )
    rules = [DEFAULT_RULES.get(rule)(mock_config) for rule in mock_config.rules]
    processor = RuleProcessor(*rules)
    result = processor.process_cf_template(template_two_roles_dict, mock_config)

    assert result.valid


def test_filter_do_not_report_anything(template_two_roles_dict):
    mock_config = Config(
        rules=["CrossAccountTrustRule"],
        aws_account_id="123456789",
        stack_name="mockstack",
        rules_config={
            "CrossAccountTrustRule": RuleConfig(
                filters=[
                    Filter(rule_mode=RuleMode.WHITELISTED, eval={"eq": [{"ref": "config.stack_name"}, "mockstack"]})
                ],
            )
        },
    )
    rules = [DEFAULT_RULES.get(rule)(mock_config) for rule in mock_config.rules]
    processor = RuleProcessor(*rules)
    result = processor.process_cf_template(template_two_roles_dict, mock_config)

    assert result.valid


def test_non_whitelisted_stacks_are_reported_normally(template_two_roles_dict, expected_result_two_roles):
    mock_stack_whitelist = {"mockstack": ["CrossAccountTrustRule"]}
    mock_config = Config(
        rules=["CrossAccountTrustRule"],
        aws_account_id="123456789",
        stack_name="anotherstack",
        stack_whitelist=mock_stack_whitelist,
    )
    rules = [DEFAULT_RULES.get(rule)(mock_config) for rule in mock_config.rules]
    processor = RuleProcessor(*rules)
    result = processor.process_cf_template(template_two_roles_dict, mock_config)
    assert not result.valid
    assert result.failed_rules == expected_result_two_roles


def test_non_matching_filters_are_reported_normally(template_two_roles_dict, expected_result_two_roles):
    mock_config = Config(
        rules=["CrossAccountTrustRule"],
        aws_account_id="123456789",
        stack_name="mockstack",
        rules_config={
            "CrossAccountTrustRule": RuleConfig(
                filters=[
                    Filter(rule_mode=RuleMode.WHITELISTED, eval={"eq": [{"ref": "config.stack_name"}, "anotherstack"]})
                ],
            )
        },
    )
    rules = [DEFAULT_RULES.get(rule)(mock_config) for rule in mock_config.rules]
    processor = RuleProcessor(*rules)
    result = processor.process_cf_template(template_two_roles_dict, mock_config)
    assert not result.valid
    assert result.failed_rules == expected_result_two_roles


def test_service_is_not_blocked(template_valid_with_service):
    rule = CrossAccountTrustRule(Config())
    result = rule.invoke(template_valid_with_service)

    assert result.valid
    assert len(result.failed_rules) == 0
    assert len(result.failed_monitored_rules) == 0


def test_canonical_id_is_not_blocked(template_valid_with_canonical_id):
    rule = CrossAccountTrustRule(Config())
    result = rule.invoke(template_valid_with_canonical_id)

    assert result.valid
    assert len(result.failed_rules) == 0
    assert len(result.failed_monitored_rules) == 0


def test_org_accounts_cause_cross_account_issues(template_one_role):
    rule = CrossAccountTrustRule(Config(aws_account_id="123456789", aws_principals=["999999999"]))
    result = rule.invoke(template_one_role)

    assert not result.valid
    assert len(result.failed_rules) == 1
    assert len(result.failed_monitored_rules) == 0
    failed_rule = result.failed_rules[0]
    assert failed_rule.reason == (
        "RootRole has forbidden cross-account trust relationship with arn:aws:iam::999999999:role/someuser@bla.com"
    )


@pytest.mark.parametrize(
    "principal",
    [
        "arn:aws:iam::999999999:root",
        "arn:aws:iam::*:root",
        "arn:aws:iam::*:*",
        "arn:aws:iam::*:root*",
        "arn:aws:iam::*:not-root*",
        "*",
    ],
)
def test_kms_cross_account_failure(principal):
    rule = KMSKeyCrossAccountTrustRule(Config(aws_account_id="123456789", aws_principals=["999999999"]))
    model = get_cfmodel_from("rules/CrossAccountTrustRule/kms_basic.yml").resolve(extra_params={"Principal": principal})
    result = rule.invoke(model)
    assert not result.valid
    assert len(result.failed_rules) == 1
    assert len(result.failed_monitored_rules) == 0
    failed_rule = result.failed_rules[0]
    assert failed_rule.reason == (
        f"KMSKey has forbidden cross-account policy allow with {principal} for an KMS Key Policy"
    )


@pytest.mark.parametrize(
    "principal", ["arn:aws:iam::123456789:root", "arn:aws:iam::123456789:not-root", "arn:aws:iam::123456789:not-root*"],
)
def test_kms_cross_account_success(principal):
    rule = KMSKeyCrossAccountTrustRule(Config(aws_account_id="123456789", aws_principals=["999999999"]))
    model = get_cfmodel_from("rules/CrossAccountTrustRule/kms_basic.yml").resolve(extra_params={"Principal": principal})
    result = rule.invoke(model)
    assert result.valid


def test_sts_valid(template_valid_with_sts):
    rule = KMSKeyCrossAccountTrustRule(Config(aws_account_id="123456789", aws_principals=["999999999"]))
    result = rule.invoke(template_valid_with_sts)

    assert result.valid
    assert len(result.failed_rules) == 0
    assert len(result.failed_monitored_rules) == 0


def test_sts_failure(template_invalid_with_sts):
    rule = KMSKeyCrossAccountTrustRule(Config(aws_account_id="123456789", aws_principals=["999999999"]))
    result = rule.invoke(template_invalid_with_sts)

    assert not result.valid
    assert len(result.failed_rules) == 1
    assert len(result.failed_monitored_rules) == 0
    failed_rule = result.failed_rules[0]
    assert failed_rule.reason == (
        "KmsMasterKey has forbidden cross-account policy allow with arn:aws:sts::999999999:assumed-role/test-role/session for an KMS Key Policy"
    )
