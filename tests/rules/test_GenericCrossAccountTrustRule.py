import pytest

from cfripper.config.config import Config
from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rules import GenericCrossAccountTrustRule
from tests.utils import compare_lists_of_failures, get_cfmodel_from


@pytest.fixture()
def s3_bucket_cross_account():
    return get_cfmodel_from("rules/S3CrossAccountTrustRule/s3_bucket_cross_account.json").resolve()


@pytest.fixture()
def s3_bucket_cross_account_from_aws_service():
    return get_cfmodel_from("rules/S3CrossAccountTrustRule/s3_bucket_cross_account_from_aws_service.json").resolve()


@pytest.fixture()
def s3_bucket_cross_account_and_normal():
    return get_cfmodel_from("rules/S3CrossAccountTrustRule/s3_bucket_cross_account_and_normal.json").resolve()


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
def template_iam_role_to_jump_to_another_account():
    return get_cfmodel_from("rules/CrossAccountTrustRule/iam_role_to_jump_to_another_account.yaml").resolve()


@pytest.fixture()
def template_one_role():
    return get_cfmodel_from("rules/CrossAccountTrustRule/iam_root_role_cross_account.json").resolve()


def test_iam_role_to_jump_to_another_account(template_iam_role_to_jump_to_another_account):
    rule = GenericCrossAccountTrustRule(Config(aws_account_id="123456789"))
    result = rule.invoke(template_iam_role_to_jump_to_another_account)
    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_iam_role_is_checked_in_generic_rule(template_one_role):
    rule = GenericCrossAccountTrustRule(Config(aws_account_id="123456789"))
    result = rule.invoke(template_one_role)
    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="RootRole has forbidden cross-account with `arn:aws:iam::999999999:role/someuser@bla.com`",
                risk_value=RuleRisk.MEDIUM,
                rule="GenericCrossAccountTrustRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"RootRole"},
                resource_types={"AWS::IAM::Role"},
            )
        ],
    )


def test_s3_bucket_cross_account_with_generic(s3_bucket_cross_account):
    rule = GenericCrossAccountTrustRule(Config(aws_account_id="123456789"))
    result = rule.invoke(s3_bucket_cross_account)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="S3BucketPolicyAccountAccess has forbidden cross-account with `arn:aws:iam::987654321:root`",
                risk_value=RuleRisk.MEDIUM,
                rule="GenericCrossAccountTrustRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"S3BucketPolicyAccountAccess"},
                resource_types={"AWS::S3::BucketPolicy"},
            )
        ],
    )


def test_s3_bucket_cross_account_and_normal_with_generic(s3_bucket_cross_account_and_normal):
    rule = GenericCrossAccountTrustRule(Config(aws_account_id="123456789012"))
    result = rule.invoke(s3_bucket_cross_account_and_normal)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="S3BucketPolicyAccountAccess has forbidden cross-account with `arn:aws:iam::666555444333:root`",
                risk_value=RuleRisk.MEDIUM,
                rule="GenericCrossAccountTrustRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"S3BucketPolicyAccountAccess"},
                resource_types={"AWS::S3::BucketPolicy"},
            )
        ],
    )


def test_s3_bucket_cross_account_and_normal_with_org_aws_account_with_generic(s3_bucket_cross_account_and_normal):
    rule = GenericCrossAccountTrustRule(Config(aws_account_id="123456789012", aws_principals=["666555444333"]))
    result = rule.invoke(s3_bucket_cross_account_and_normal)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="S3BucketPolicyAccountAccess has forbidden cross-account with `arn:aws:iam::666555444333:root`",
                risk_value=RuleRisk.MEDIUM,
                rule="GenericCrossAccountTrustRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"S3BucketPolicyAccountAccess"},
                resource_types={"AWS::S3::BucketPolicy"},
            )
        ],
    )


def test_s3_bucket_cross_account_for_current_account_with_generic(s3_bucket_cross_account):
    rule = GenericCrossAccountTrustRule(Config(aws_account_id="987654321"))
    result = rule.invoke(s3_bucket_cross_account)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_s3_bucket_cross_account_from_aws_service_with_generic(s3_bucket_cross_account_from_aws_service):
    rule = GenericCrossAccountTrustRule(Config(aws_account_id="123456789"))
    result = rule.invoke(s3_bucket_cross_account_from_aws_service)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_generic_rule_supports_filter_config(s3_bucket_cross_account_and_normal, default_allow_all_config):
    rule = GenericCrossAccountTrustRule(default_allow_all_config)
    result = rule.invoke(s3_bucket_cross_account_and_normal)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


@pytest.mark.parametrize(
    "principal",
    ["arn:aws:iam::123456789:root", "arn:aws:iam::123456789:not-root", "arn:aws:iam::123456789:not-root*"],
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
                reason=f"TestDomain has forbidden cross-account with `{principal}`",
                risk_value=RuleRisk.MEDIUM,
                rule="GenericCrossAccountTrustRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"TestDomain"},
                resource_types={"AWS::OpenSearchService::Domain"},
            )
        ],
    )


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
                    reason="TestDomain has forbidden cross-account with `arn:aws:sts::999999999:assumed-role/test-role/session`",
                    risk_value=RuleRisk.MEDIUM,
                    rule="GenericCrossAccountTrustRule",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids={"TestDomain"},
                    resource_types={"AWS::Elasticsearch::Domain"},
                )
            ],
        ),
        (template_valid_with_sts(), True, []),
        (
            template_invalid_with_sts(),
            False,
            [
                Failure(
                    granularity=RuleGranularity.RESOURCE,
                    reason="KmsMasterKey has forbidden cross-account with `arn:aws:sts::999999999:assumed-role/test-role/session`",
                    risk_value=RuleRisk.MEDIUM,
                    rule="GenericCrossAccountTrustRule",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids={"KmsMasterKey"},
                    resource_types={"AWS::KMS::Key"},
                )
            ],
        ),
        (template_opensearch_domain_without_access_policies(), True, []),
        (template_valid_with_sts_opensearch_domain(), True, []),
        (
            template_invalid_with_sts_opensearch_domain(),
            False,
            [
                Failure(
                    granularity=RuleGranularity.RESOURCE,
                    reason="TestDomain has forbidden cross-account with `arn:aws:sts::999999999:assumed-role/test-role/session`",
                    risk_value=RuleRisk.MEDIUM,
                    rule="GenericCrossAccountTrustRule",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids={"TestDomain"},
                    resource_types={"AWS::OpenSearchService::Domain"},
                )
            ],
        ),
        (template_generic_resource_no_policies(), True, []),
        (template_two_generic_resources_no_policies(), True, []),
        (
            template_invalid_generic_resource(),
            False,
            [
                Failure(
                    granularity=RuleGranularity.RESOURCE,
                    reason="NonexistentResource has forbidden cross-account with `arn:aws:sts::999999999:assumed-role/test-role/session`",
                    risk_value=RuleRisk.MEDIUM,
                    rule="GenericCrossAccountTrustRule",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids={"NonexistentResource"},
                    resource_types={"AWS::Non::Existent"},
                )
            ],
        ),
        (
            template_invalid_generic_resources(),
            False,
            [
                Failure(
                    granularity=RuleGranularity.RESOURCE,
                    reason="NonexistentResource has forbidden cross-account with `arn:aws:sts::999999999:assumed-role/test-role/session`",
                    risk_value=RuleRisk.MEDIUM,
                    rule="GenericCrossAccountTrustRule",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids={"NonexistentResource"},
                    resource_types={"AWS::Non::Existent"},
                ),
                Failure(
                    granularity=RuleGranularity.RESOURCE,
                    reason="NonexistentResourceSecond has forbidden cross-account with `arn:aws:sts::999999999:assumed-role/test-role/session`",
                    risk_value=RuleRisk.MEDIUM,
                    rule="GenericCrossAccountTrustRule",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids={"NonexistentResourceSecond"},
                    resource_types={"AWS::Non::Existent"},
                ),
            ],
        ),
        (
            template_mixed_invalid_generic_resources(),
            False,
            [
                Failure(
                    granularity=RuleGranularity.RESOURCE,
                    reason="NonexistentResourceSecond has forbidden cross-account with `arn:aws:sts::999999999:assumed-role/test-role/session`",
                    risk_value=RuleRisk.MEDIUM,
                    rule="GenericCrossAccountTrustRule",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids={"NonexistentResourceSecond"},
                    resource_types={"AWS::Non::Existent"},
                ),
            ],
        ),
        (template_generic_resource_no_policies(), True, []),
        (template_two_generic_resources_no_policies(), True, []),
        (
            template_generic_resource_with_cross_account_policy(),
            False,
            [
                Failure(
                    granularity=RuleGranularity.RESOURCE,
                    reason="NonexistentResource has forbidden cross-account with `arn:aws:iam::999999999:role/someuser@bla.com`",
                    risk_value=RuleRisk.MEDIUM,
                    rule="GenericCrossAccountTrustRule",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids={"NonexistentResource"},
                    resource_types={"AWS::Non::Existent"},
                )
            ],
        ),
        (
            template_generic_resources_with_cross_account_policies(),
            False,
            [
                Failure(
                    granularity=RuleGranularity.RESOURCE,
                    reason="NonexistentResource has forbidden cross-account with `arn:aws:iam::999999999:role/someuser@bla.com`",
                    risk_value=RuleRisk.MEDIUM,
                    rule="GenericCrossAccountTrustRule",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids={"NonexistentResource"},
                    resource_types={"AWS::Non::Existent"},
                ),
                Failure(
                    granularity=RuleGranularity.RESOURCE,
                    reason="NonexistentResourceTwo has forbidden cross-account with `arn:aws:iam::999999999:role/someuser@bla.com`",
                    risk_value=RuleRisk.MEDIUM,
                    rule="GenericCrossAccountTrustRule",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids={"NonexistentResourceTwo"},
                    resource_types={"AWS::Non::Existent"},
                ),
            ],
        ),
        (
            template_generic_resources_with_mixed_cross_account_policy_and_no_policy(),
            False,
            [
                Failure(
                    granularity=RuleGranularity.RESOURCE,
                    reason="NonexistentResourceTwo has forbidden cross-account with `arn:aws:iam::999999999:role/someuser@bla.com`",
                    risk_value=RuleRisk.MEDIUM,
                    rule="GenericCrossAccountTrustRule",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids={"NonexistentResourceTwo"},
                    resource_types={"AWS::Non::Existent"},
                )
            ],
        ),
    ],
)
def test_generic_cross_account_rule_for_resources_with_set_principals(template, is_valid, failures):
    rule = GenericCrossAccountTrustRule(Config(aws_account_id="123456789", aws_principals=["999999999"]))
    result = rule.invoke(template)
    assert result.valid == is_valid
    assert compare_lists_of_failures(result.failures, failures)


@pytest.mark.parametrize(
    "principal",
    ["arn:aws:iam::123456789:root", "arn:aws:iam::123456789:not-root", "arn:aws:iam::123456789:not-root*"],
)
def test_generic_cross_account_es_domain_cross_account_success(principal):
    rule = GenericCrossAccountTrustRule(Config(aws_account_id="123456789", aws_principals=["999999999"]))
    model = get_cfmodel_from("rules/CrossAccountTrustRule/es_domain_basic.yml").resolve(
        extra_params={"Principal": principal}
    )
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
def test_generic_cross_account_rule_es_domain_cross_account_failure(principal):
    rule = GenericCrossAccountTrustRule(Config(aws_account_id="123456789", aws_principals=["999999999"]))
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
                reason=f"TestDomain has forbidden cross-account with `{principal}`",
                risk_value=RuleRisk.MEDIUM,
                rule="GenericCrossAccountTrustRule",
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
def test_generic_cross_account_with_kms_key_success(principal):
    rule = GenericCrossAccountTrustRule(Config(aws_account_id="123456789", aws_principals=["999999999"]))
    model = get_cfmodel_from("rules/CrossAccountTrustRule/kms_basic.yml").resolve(extra_params={"Principal": principal})
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
def test_generic_cross_account_with_kms_key_failure(principal):
    rule = GenericCrossAccountTrustRule(Config(aws_account_id="123456789", aws_principals=["999999999"]))
    model = get_cfmodel_from("rules/CrossAccountTrustRule/kms_basic.yml").resolve(extra_params={"Principal": principal})
    result = rule.invoke(model)
    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason=f"KMSKey has forbidden cross-account with `{principal}`",
                risk_value=RuleRisk.MEDIUM,
                rule="GenericCrossAccountTrustRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"KMSKey"},
                resource_types={"AWS::KMS::Key"},
            )
        ],
    )
