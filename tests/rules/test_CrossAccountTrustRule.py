import pytest

from cfripper.config.config import Config
from cfripper.config.filter import Filter
from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rule_processor import RuleProcessor
from cfripper.rules import DEFAULT_RULES
from cfripper.rules.cross_account_trust import (
    CrossAccountTrustRule,
    ElasticsearchDomainCrossAccountTrustRule,
    KMSKeyCrossAccountTrustRule,
    OpenSearchDomainCrossAccountTrustRule,
)
from tests.utils import compare_lists_of_failures, get_cfmodel_from


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


def template_valid_with_sts():
    return get_cfmodel_from("rules/CrossAccountTrustRule/valid_with_sts.yml").resolve()


def template_valid_with_sts_es_domain():
    return get_cfmodel_from("rules/CrossAccountTrustRule/valid_with_sts_es_domain.yml").resolve()


def template_valid_with_sts_opensearch_domain():
    return get_cfmodel_from("rules/CrossAccountTrustRule/valid_with_sts_opensearch_domain.yml").resolve()


def template_invalid_with_sts():
    return get_cfmodel_from("rules/CrossAccountTrustRule/invalid_with_sts.yml").resolve()


def template_invalid_with_sts_es_domain():
    return get_cfmodel_from("rules/CrossAccountTrustRule/invalid_with_sts_es_domain.yml").resolve()


def template_invalid_with_sts_opensearch_domain():
    return get_cfmodel_from("rules/CrossAccountTrustRule/invalid_with_sts_opensearch_domain.yml").resolve()


def template_es_domain_without_access_policies():
    return get_cfmodel_from("rules/CrossAccountTrustRule/es_domain_without_access_policies.yml").resolve()


def template_opensearch_domain_without_access_policies():
    return get_cfmodel_from("rules/CrossAccountTrustRule/opensearch_domain_without_access_policies.yml").resolve()


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
            actions=None,
            granularity=RuleGranularity.RESOURCE,
            resource_types={"AWS::IAM::Role"},
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
            actions=None,
            granularity=RuleGranularity.RESOURCE,
            resource_types={"AWS::IAM::Role"},
        ),
    ]


def test_report_format_is_the_one_expected(template_one_role):
    rule = CrossAccountTrustRule(Config(aws_account_id="123456789"))
    result = rule.invoke(template_one_role)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                rule="CrossAccountTrustRule",
                reason=(
                    "RootRole has forbidden cross-account trust relationship with arn:aws:iam::999999999:role/"
                    "someuser@bla.com"
                ),
                rule_mode=RuleMode.BLOCKING,
                risk_value=RuleRisk.MEDIUM,
                resource_ids={"RootRole"},
                actions=None,
                granularity=RuleGranularity.RESOURCE,
                resource_types={"AWS::IAM::Role"},
            ),
        ],
    )


def test_filter_works_as_expected(template_two_roles_dict, expected_result_two_roles):
    config = Config(
        rules=["CrossAccountTrustRule"],
        aws_account_id="123456789",
        stack_name="mockstack",
        rules_filters=[
            Filter(
                rule_mode=RuleMode.ALLOWED,
                eval={
                    "and": [
                        {"eq": [{"ref": "config.stack_name"}, "mockstack"]},
                        {"eq": [{"ref": "logical_id"}, "RootRoleOne"]},
                    ]
                },
                rules={"CrossAccountTrustRule"},
            )
        ],
    )
    rules = [DEFAULT_RULES.get(rule)(config) for rule in config.rules]
    processor = RuleProcessor(*rules)
    result = processor.process_cf_template(template_two_roles_dict, config)

    assert not result.valid
    assert compare_lists_of_failures(result.failures, expected_result_two_roles[-1:])


def test_filter_works_as_expected_with_rules_config_file(
    template_two_roles_dict, expected_result_two_roles, test_files_location
):
    config = Config(
        rules=["CrossAccountTrustRule"],
        aws_account_id="123456789",
        stack_name="mockstack",
    )
    config.load_rules_config_file(open(f"{test_files_location}/config/rules_config_CrossAccountTrustRule.py"))
    config.add_filters_from_dir(f"{test_files_location}/filters")
    rules = [DEFAULT_RULES.get(rule)(config) for rule in config.rules]
    processor = RuleProcessor(*rules)
    result = processor.process_cf_template(template_two_roles_dict, config)

    assert not result.valid
    assert compare_lists_of_failures(result.failures, expected_result_two_roles[-1:])


def test_filter_do_not_report_anything(template_two_roles_dict):
    mock_config = Config(
        rules=["CrossAccountTrustRule"],
        aws_account_id="123456789",
        stack_name="mockstack",
        rules_filters=[
            Filter(
                rule_mode=RuleMode.ALLOWED,
                eval={"eq": [{"ref": "config.stack_name"}, "mockstack"]},
                rules={"CrossAccountTrustRule"},
            )
        ],
    )
    rules = [DEFAULT_RULES.get(rule)(mock_config) for rule in mock_config.rules]
    processor = RuleProcessor(*rules)
    result = processor.process_cf_template(template_two_roles_dict, mock_config)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_service_is_not_blocked(template_valid_with_service):
    rule = CrossAccountTrustRule(Config())
    result = rule.invoke(template_valid_with_service)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_canonical_id_is_not_blocked(template_valid_with_canonical_id):
    rule = CrossAccountTrustRule(Config())
    result = rule.invoke(template_valid_with_canonical_id)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_org_accounts_cause_cross_account_issues(template_one_role):
    rule = CrossAccountTrustRule(Config(aws_account_id="123456789", aws_principals=["999999999"]))
    result = rule.invoke(template_one_role)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="RootRole has forbidden cross-account trust relationship with arn:aws:iam::999999999:role/someuser@bla.com",
                risk_value=RuleRisk.MEDIUM,
                rule="CrossAccountTrustRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"RootRole"},
                resource_types={"AWS::IAM::Role"},
            )
        ],
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
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason=f"KMSKey has forbidden cross-account policy allow with {principal} for an KMS Key Policy",
                risk_value=RuleRisk.MEDIUM,
                rule="KMSKeyCrossAccountTrustRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"KMSKey"},
                resource_types={"AWS::KMS::Key"},
            )
        ],
    )


@pytest.mark.parametrize(
    "principal",
    ["arn:aws:iam::123456789:root", "arn:aws:iam::123456789:not-root", "arn:aws:iam::123456789:not-root*"],
)
def test_kms_cross_account_success(principal):
    rule = KMSKeyCrossAccountTrustRule(Config(aws_account_id="123456789", aws_principals=["999999999"]))
    model = get_cfmodel_from("rules/CrossAccountTrustRule/kms_basic.yml").resolve(extra_params={"Principal": principal})
    result = rule.invoke(model)
    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


@pytest.mark.parametrize(
    "template,is_valid,failures",
    [
        (template_valid_with_sts(), True, []),
        (
            template_invalid_with_sts(),
            False,
            [
                Failure(
                    granularity=RuleGranularity.RESOURCE,
                    reason="KmsMasterKey has forbidden cross-account policy allow with arn:aws:sts::999999999:assumed-role/test-role/session for an KMS Key Policy",
                    risk_value=RuleRisk.MEDIUM,
                    rule="KMSKeyCrossAccountTrustRule",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids={"KmsMasterKey"},
                    resource_types={"AWS::KMS::Key"},
                )
            ],
        ),
    ],
)
def test_kms_key_cross_account_sts(template, is_valid, failures):
    rule = KMSKeyCrossAccountTrustRule(Config(aws_account_id="123456789", aws_principals=["999999999"]))
    result = rule.invoke(template)
    assert result.valid == is_valid
    assert compare_lists_of_failures(result.failures, failures)


def test_kms_key__without_policy():
    rule = KMSKeyCrossAccountTrustRule(Config(aws_account_id="123456789", aws_principals=["999999999"]))
    model = get_cfmodel_from("rules/CrossAccountTrustRule/kms_key_without_policy.yml")
    result = rule.invoke(model)
    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


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
def test_es_domain_cross_account_failure(principal):
    rule = ElasticsearchDomainCrossAccountTrustRule(Config(aws_account_id="123456789", aws_principals=["999999999"]))
    model = get_cfmodel_from("rules/CrossAccountTrustRule/es_domain_basic.yml").resolve(
        extra_params={"Principal": principal}
    )
    result = rule.invoke(model)
    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason=f"TestDomain has forbidden cross-account policy allow with {principal} for an ES domain policy.",
                risk_value=RuleRisk.MEDIUM,
                rule="ElasticsearchDomainCrossAccountTrustRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"TestDomain"},
                resource_types={"AWS::Elasticsearch::Domain"},
            )
        ],
    )


@pytest.mark.parametrize(
    "principal",
    ["arn:aws:iam::123456789:root", "arn:aws:iam::123456789:not-root", "arn:aws:iam::123456789:not-root*"],
)
def test_es_domain_cross_account_success(principal):
    rule = ElasticsearchDomainCrossAccountTrustRule(Config(aws_account_id="123456789", aws_principals=["999999999"]))
    model = get_cfmodel_from("rules/CrossAccountTrustRule/es_domain_basic.yml").resolve(
        extra_params={"Principal": principal}
    )
    result = rule.invoke(model)
    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


@pytest.mark.parametrize(
    "template,is_valid,failures",
    [
        (template_es_domain_without_access_policies(), True, []),
        (template_valid_with_sts_es_domain(), True, []),
        (
            template_invalid_with_sts_es_domain(),
            False,
            [
                Failure(
                    granularity=RuleGranularity.RESOURCE,
                    reason="TestDomain has forbidden cross-account policy allow with arn:aws:sts::999999999:assumed-role/test-role/session for an ES domain policy.",
                    risk_value=RuleRisk.MEDIUM,
                    rule="ElasticsearchDomainCrossAccountTrustRule",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids={"TestDomain"},
                    resource_types={"AWS::Elasticsearch::Domain"},
                )
            ],
        ),
    ],
)
def test_elasticsearch_domain_cross_account_rule_with_set_principals(template, is_valid, failures):
    rule = ElasticsearchDomainCrossAccountTrustRule(Config(aws_account_id="123456789", aws_principals=["999999999"]))
    result = rule.invoke(template)
    assert result.valid == is_valid
    assert compare_lists_of_failures(result.failures, failures)


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
def test_opensearch_domain_cross_account_failure(principal):
    rule = OpenSearchDomainCrossAccountTrustRule(Config(aws_account_id="123456789", aws_principals=["999999999"]))
    model = get_cfmodel_from("rules/CrossAccountTrustRule/opensearch_domain_basic.yml").resolve(
        extra_params={"Principal": principal}
    )
    result = rule.invoke(model)
    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason=f"TestDomain has forbidden cross-account policy allow with {principal} for an OpenSearch domain policy.",
                risk_value=RuleRisk.MEDIUM,
                rule="OpenSearchDomainCrossAccountTrustRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"TestDomain"},
                resource_types={"AWS::OpenSearchService::Domain"},
            )
        ],
    )


@pytest.mark.parametrize(
    "principal",
    ["arn:aws:iam::123456789:root", "arn:aws:iam::123456789:not-root", "arn:aws:iam::123456789:not-root*"],
)
def test_opensearch_domain_cross_account_success(principal):
    rule = OpenSearchDomainCrossAccountTrustRule(Config(aws_account_id="123456789", aws_principals=["999999999"]))
    model = get_cfmodel_from("rules/CrossAccountTrustRule/opensearch_domain_basic.yml").resolve(
        extra_params={"Principal": principal}
    )
    result = rule.invoke(model)
    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


@pytest.mark.parametrize(
    "template,is_valid,failures",
    [
        (template_opensearch_domain_without_access_policies(), True, []),
        (template_valid_with_sts_opensearch_domain(), True, []),
        (
            template_invalid_with_sts_opensearch_domain(),
            False,
            [
                Failure(
                    granularity=RuleGranularity.RESOURCE,
                    reason="TestDomain has forbidden cross-account policy allow with arn:aws:sts::999999999:assumed-role/test-role/session for an OpenSearch domain policy.",
                    risk_value=RuleRisk.MEDIUM,
                    rule="OpenSearchDomainCrossAccountTrustRule",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids={"TestDomain"},
                    resource_types={"AWS::OpenSearchService::Domain"},
                )
            ],
        ),
    ],
)
def test_opensearch_domain_with_different_principals_in_rule_config(template, is_valid, failures):
    rule = OpenSearchDomainCrossAccountTrustRule(Config(aws_account_id="123456789", aws_principals=["999999999"]))
    result = rule.invoke(template)
    assert result.valid == is_valid
    assert compare_lists_of_failures(result.failures, failures)
