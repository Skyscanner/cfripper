import pytest

from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rules.hardcoded_RDS_password import HardcodedRDSPasswordRule
from tests.utils import compare_lists_of_failures, get_cfmodel_from


@pytest.fixture()
def bad_template_instances():
    return get_cfmodel_from("rules/HardcodedRDSPasswordRule/bad_template.json").resolve()


@pytest.fixture()
def bad_template_clusters():
    return get_cfmodel_from("rules/HardcodedRDSPasswordRule/bad_template_cluster.json").resolve()


@pytest.fixture()
def good_template_clusters_and_instances():
    return get_cfmodel_from("rules/HardcodedRDSPasswordRule/rds_good_cluster_good_instances.json").resolve()


@pytest.fixture()
def bad_template_good_clusters_with_bad_instances():
    return get_cfmodel_from("rules/HardcodedRDSPasswordRule/rds_good_cluster_bad_instances.json").resolve()


@pytest.fixture()
def bad_template_clusters_with_bad_instances():
    return get_cfmodel_from("rules/HardcodedRDSPasswordRule/bad_clusters_and_instances.json").resolve()


def test_failures_are_raised_for_instances(bad_template_instances):
    rule = HardcodedRDSPasswordRule(None)
    result = rule.invoke(bad_template_instances)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="RDS Instance password parameter missing NoEcho for BadDb3.",
                risk_value=RuleRisk.MEDIUM,
                rule="HardcodedRDSPasswordRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"BadDb3"},
                resource_types={"AWS::RDS::DBInstance"},
            ),
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="Default RDS Instance password parameter (readable in plain-text) for BadDb5.",
                risk_value=RuleRisk.MEDIUM,
                rule="HardcodedRDSPasswordRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"BadDb5"},
                resource_types={"AWS::RDS::DBInstance"},
            ),
        ],
    )


def test_failures_are_raised_for_clusters(bad_template_clusters):
    rule = HardcodedRDSPasswordRule(None)
    result = rule.invoke(bad_template_clusters)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="RDS Cluster password parameter missing NoEcho for BadCluster1.",
                risk_value=RuleRisk.MEDIUM,
                rule="HardcodedRDSPasswordRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"BadCluster1"},
                resource_types={"AWS::RDS::DBCluster"},
            )
        ],
    )


def test_passed_cluster_pw_protected(good_template_clusters_and_instances):
    rule = HardcodedRDSPasswordRule(None)
    result = rule.invoke(good_template_clusters_and_instances)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_failures_are_raised_for_instances_without_protected_clusters(bad_template_good_clusters_with_bad_instances):
    rule = HardcodedRDSPasswordRule(None)
    result = rule.invoke(bad_template_good_clusters_with_bad_instances)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="Default RDS Instance password parameter (readable in plain-text) for BadDb5.",
                risk_value=RuleRisk.MEDIUM,
                rule="HardcodedRDSPasswordRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"BadDb5"},
                resource_types={"AWS::RDS::DBInstance"},
            )
        ],
    )


def test_failures_are_raised_for_bad_instances_and_bad_clusters(bad_template_clusters_with_bad_instances):
    rule = HardcodedRDSPasswordRule(None)
    result = rule.invoke(bad_template_clusters_with_bad_instances)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="Default RDS Cluster password parameter (readable in plain-text) for BadCluster99.",
                risk_value=RuleRisk.MEDIUM,
                rule="HardcodedRDSPasswordRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"BadCluster99"},
                resource_types={"AWS::RDS::DBCluster"},
            ),
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="RDS Instance password parameter missing NoEcho for BadDb33.",
                risk_value=RuleRisk.MEDIUM,
                rule="HardcodedRDSPasswordRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"BadDb33"},
                resource_types={"AWS::RDS::DBInstance"},
            ),
        ],
    )


def test_rule_supports_filter_config(bad_template_clusters_with_bad_instances, default_allow_all_config):
    rule = HardcodedRDSPasswordRule(default_allow_all_config)
    result = rule.invoke(bad_template_clusters_with_bad_instances)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])
