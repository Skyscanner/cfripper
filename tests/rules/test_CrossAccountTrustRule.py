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
    GenericCrossAccountTrustRule,
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


@pytest.fixture()
def template_valid_with_sts():
    return get_cfmodel_from("rules/CrossAccountTrustRule/valid_with_sts.yml").resolve()


@pytest.fixture()
def template_valid_with_sts_es_domain():
    return get_cfmodel_from("rules/CrossAccountTrustRule/valid_with_sts_es_domain.yml").resolve()


def template_valid_with_sts_opensearch_domain():
    return get_cfmodel_from("rules/CrossAccountTrustRule/valid_with_sts_opensearch_domain.yml").resolve()


@pytest.fixture()
def template_invalid_with_sts():
    return get_cfmodel_from("rules/CrossAccountTrustRule/invalid_with_sts.yml").resolve()


@pytest.fixture()
def template_invalid_with_sts_es_domain():
    return get_cfmodel_from("rules/CrossAccountTrustRule/invalid_with_sts_es_domain.yml").resolve()


def template_invalid_with_sts_opensearch_domain():
    return get_cfmodel_from("rules/CrossAccountTrustRule/invalid_with_sts_opensearch_domain.yml").resolve()


@pytest.fixture()
def template_es_domain_without_access_policies():
    return get_cfmodel_from("rules/CrossAccountTrustRule/es_domain_without_access_policies.yml").resolve()


def template_opensearch_domain_without_access_policies():
    return get_cfmodel_from("rules/CrossAccountTrustRule/opensearch_domain_without_access_policies.yml").resolve()


def template_generic_resource_no_policies():
    return get_cfmodel_from("rules/CrossAccountTrustRule/generic_resource_no_policies.json").resolve()


def template_two_generic_resources_no_policies():
    return get_cfmodel_from("rules/CrossAccountTrustRule/generic_resources_no_policies.json").resolve()


def template_generic_resource_with_cross_account_policy():
    return get_cfmodel_from("rules/CrossAccountTrustRule/generic_resource_with_cross_account_policy.json").resolve()


def template_generic_resources_with_cross_account_policies():
    return get_cfmodel_from("rules/CrossAccountTrustRule/generic_resources_with_cross_account_policies.json").resolve()


def template_generic_resources_with_mixed_cross_account_policy_and_no_policy():
    return get_cfmodel_from(
        "rules/CrossAccountTrustRule/generic_resources_with_mixed_cross_account_policy_and_no_policy.json"
    ).resolve()


def template_invalid_generic_resource():
    return get_cfmodel_from("rules/CrossAccountTrustRule/invalid_generic_resource.json").resolve()


def template_invalid_generic_resources():
    return get_cfmodel_from("rules/CrossAccountTrustRule/invalid_generic_resources.json").resolve()


def template_mixed_invalid_generic_resources():
    return get_cfmodel_from("rules/CrossAccountTrustRule/mixed_invalid_generic_resources.json").resolve()


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
    config = Config(rules=["CrossAccountTrustRule"], aws_account_id="123456789", stack_name="mockstack",)
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
            )
        ],
    )


@pytest.mark.parametrize(
    "principal", ["arn:aws:iam::123456789:root", "arn:aws:iam::123456789:not-root", "arn:aws:iam::123456789:not-root*"],
)
def test_kms_cross_account_success(principal):
    rule = KMSKeyCrossAccountTrustRule(Config(aws_account_id="123456789", aws_principals=["999999999"]))
    model = get_cfmodel_from("rules/CrossAccountTrustRule/kms_basic.yml").resolve(extra_params={"Principal": principal})
    result = rule.invoke(model)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_sts_valid(template_valid_with_sts):
    rule = KMSKeyCrossAccountTrustRule(Config(aws_account_id="123456789", aws_principals=["999999999"]))
    result = rule.invoke(template_valid_with_sts)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_sts_failure(template_invalid_with_sts):
    rule = KMSKeyCrossAccountTrustRule(Config(aws_account_id="123456789", aws_principals=["999999999"]))
    result = rule.invoke(template_invalid_with_sts)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="KmsMasterKey has forbidden cross-account policy allow with arn:aws:sts::999999999:assumed-role/test-role/session for an KMS Key Policy",
                risk_value=RuleRisk.MEDIUM,
                rule="KMSKeyCrossAccountTrustRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"KmsMasterKey"},
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
            )
        ],
    )


@pytest.mark.parametrize(
    "principal", ["arn:aws:iam::123456789:root", "arn:aws:iam::123456789:not-root", "arn:aws:iam::123456789:not-root*"],
)
def test_es_domain_cross_account_success(principal):
    rule = ElasticsearchDomainCrossAccountTrustRule(Config(aws_account_id="123456789", aws_principals=["999999999"]))
    model = get_cfmodel_from("rules/CrossAccountTrustRule/es_domain_basic.yml").resolve(
        extra_params={"Principal": principal}
    )
    result = rule.invoke(model)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_sts_valid_es_domain(template_valid_with_sts_es_domain):
    rule = ElasticsearchDomainCrossAccountTrustRule(Config(aws_account_id="123456789", aws_principals=["999999999"]))
    result = rule.invoke(template_valid_with_sts_es_domain)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_sts_failure_es_domain(template_invalid_with_sts_es_domain):
    rule = ElasticsearchDomainCrossAccountTrustRule(Config(aws_account_id="123456789", aws_principals=["999999999"]))
    result = rule.invoke(template_invalid_with_sts_es_domain)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="TestDomain has forbidden cross-account policy allow with arn:aws:sts::999999999:assumed-role/test-role/session for an ES domain policy.",
                risk_value=RuleRisk.MEDIUM,
                rule="ElasticsearchDomainCrossAccountTrustRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"TestDomain"},
            )
        ],
    )


def test_es_domain_without_access_policies(template_es_domain_without_access_policies):
    rule = ElasticsearchDomainCrossAccountTrustRule(Config(aws_account_id="123456789", aws_principals=["999999999"]))
    result = rule.invoke(template_es_domain_without_access_policies)

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
def test_generic_cross_account_for_opensearch_domain_different_principals(principal):
    rule = GenericCrossAccountTrustRule(Config(aws_account_id="123456789", aws_principals=["999999999"]))
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
                reason=f"TestDomain has forbidden cross-account with {principal}",
                risk_value=RuleRisk.MEDIUM,
                rule="GenericCrossAccountTrustRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"TestDomain"},
            )
        ],
    )


@pytest.mark.parametrize(
    "principal", ["arn:aws:iam::123456789:root", "arn:aws:iam::123456789:not-root", "arn:aws:iam::123456789:not-root*"],
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
    "principal", ["arn:aws:iam::123456789:root", "arn:aws:iam::123456789:not-root", "arn:aws:iam::123456789:not-root*"],
)
def test_generic_cross_account_for_opensearch_domain_with_principal_params(principal):
    rule = GenericCrossAccountTrustRule(Config(aws_account_id="123456789", aws_principals=["999999999"]))
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
                    reason="TestDomain has forbidden cross-account with arn:aws:sts::999999999:assumed-role/test-role/session",
                    risk_value=RuleRisk.MEDIUM,
                    rule="GenericCrossAccountTrustRule",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids={"TestDomain"},
                )
            ],
        ),
    ],
)
def test_generic_cross_account_rule_for_opensearch_domain_with_set_principals(template, is_valid, failures):
    rule = GenericCrossAccountTrustRule(Config(aws_account_id="123456789", aws_principals=["999999999"]))
    result = rule.invoke(template)
    assert result.valid == is_valid
    assert compare_lists_of_failures(result.failures, failures)


@pytest.mark.parametrize(
    "template,is_valid,failures",
    [
        (template_generic_resource_no_policies(), True, []),
        (template_two_generic_resources_no_policies(), True, []),
        (
            template_generic_resource_with_cross_account_policy(),
            False,
            [
                Failure(
                    granularity=RuleGranularity.RESOURCE,
                    reason="NonexistentResource has forbidden cross-account with arn:aws:iam::999999999:role/someuser@bla.com",
                    risk_value=RuleRisk.MEDIUM,
                    rule="GenericCrossAccountTrustRule",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids={"NonexistentResource"},
                )
            ],
        ),
        (
            template_generic_resources_with_cross_account_policies(),
            False,
            [
                Failure(
                    granularity=RuleGranularity.RESOURCE,
                    reason="NonexistentResource has forbidden cross-account with arn:aws:iam::999999999:role/someuser@bla.com",
                    risk_value=RuleRisk.MEDIUM,
                    rule="GenericCrossAccountTrustRule",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids={"NonexistentResource"},
                ),
                Failure(
                    granularity=RuleGranularity.RESOURCE,
                    reason="NonexistentResourceTwo has forbidden cross-account with arn:aws:iam::999999999:role/someuser@bla.com",
                    risk_value=RuleRisk.MEDIUM,
                    rule="GenericCrossAccountTrustRule",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids={"NonexistentResourceTwo"},
                ),
            ],
        ),
        (
            template_generic_resources_with_mixed_cross_account_policy_and_no_policy(),
            False,
            [
                Failure(
                    granularity=RuleGranularity.RESOURCE,
                    reason="NonexistentResourceTwo has forbidden cross-account with arn:aws:iam::999999999:role/someuser@bla.com",
                    risk_value=RuleRisk.MEDIUM,
                    rule="GenericCrossAccountTrustRule",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids={"NonexistentResourceTwo"},
                )
            ],
        ),
    ],
)
def test_generic_cross_account_trust_rule(template, is_valid, failures):
    rule = GenericCrossAccountTrustRule(Config(aws_account_id="123456789"))
    result = rule.invoke(template)
    assert result.valid == is_valid
    assert compare_lists_of_failures(result.failures, failures)


@pytest.mark.parametrize(
    "template,is_valid,failures",
    [
        (template_generic_resource_no_policies(), True, []),
        (template_two_generic_resources_no_policies(), True, []),
        (
            template_invalid_generic_resource(),
            False,
            [
                Failure(
                    granularity=RuleGranularity.RESOURCE,
                    reason="NonexistentResource has forbidden cross-account with arn:aws:sts::999999999:assumed-role/test-role/session",
                    risk_value=RuleRisk.MEDIUM,
                    rule="GenericCrossAccountTrustRule",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids={"NonexistentResource"},
                )
            ],
        ),
        (
            template_invalid_generic_resources(),
            False,
            [
                Failure(
                    granularity=RuleGranularity.RESOURCE,
                    reason="NonexistentResource has forbidden cross-account with arn:aws:sts::999999999:assumed-role/test-role/session",
                    risk_value=RuleRisk.MEDIUM,
                    rule="GenericCrossAccountTrustRule",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids={"NonexistentResource"},
                ),
                Failure(
                    granularity=RuleGranularity.RESOURCE,
                    reason="NonexistentResourceSecond has forbidden cross-account with arn:aws:sts::999999999:assumed-role/test-role/session",
                    risk_value=RuleRisk.MEDIUM,
                    rule="GenericCrossAccountTrustRule",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids={"NonexistentResourceSecond"},
                ),
            ],
        ),
        (
            template_mixed_invalid_generic_resources(),
            False,
            [
                Failure(
                    granularity=RuleGranularity.RESOURCE,
                    reason="NonexistentResourceSecond has forbidden cross-account with arn:aws:sts::999999999:assumed-role/test-role/session",
                    risk_value=RuleRisk.MEDIUM,
                    rule="GenericCrossAccountTrustRule",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids={"NonexistentResourceSecond"},
                ),
            ],
        ),
    ],
)
def test_generic_cross_account_trust_rule_different_principal(template, is_valid, failures):
    rule = GenericCrossAccountTrustRule(Config(aws_account_id="123456789", aws_principals=["999999999"]))
    result = rule.invoke(template)
    assert result.valid == is_valid
    assert compare_lists_of_failures(result.failures, failures)
