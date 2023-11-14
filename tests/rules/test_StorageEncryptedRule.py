import pytest

from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rules.storage_encrypted_rule import StorageEncryptedRule
from tests.utils import get_cfmodel_from


def test_storage_encrypted_rule_valid_results():
    rule = StorageEncryptedRule(None)
    model = get_cfmodel_from("rules/StorageEncryptedRule/encrypted_db_resource.yml")
    resolved_model = model.resolve()
    result = rule.invoke(resolved_model)

    assert result.valid
    assert result.failures == []


def test_rule_not_failing_for_aurora():
    rule = StorageEncryptedRule(None)
    model = get_cfmodel_from("rules/StorageEncryptedRule/aurora_engine_used.yml")
    resolved_model = model.resolve()
    result = rule.invoke(resolved_model)

    assert result.valid
    assert result.failures == []


@pytest.mark.parametrize(
    "template, failures",
    [
        (
            "rules/StorageEncryptedRule/missing_storage_encrypted_flag.yml",
            [
                Failure(
                    granularity=RuleGranularity.RESOURCE,
                    reason="The database some-name does not seem to be encrypted. Database resources should be "
                    "encrypted and have the property StorageEncrypted set to True.",
                    risk_value=RuleRisk.LOW,
                    rule="StorageEncryptedRule",
                    rule_mode=RuleMode.DEBUG,
                    actions=None,
                    resource_ids=None,
                    resource_types={"AWS::RDS::DBInstance"},
                )
            ],
        ),
        (
            "rules/StorageEncryptedRule/two_resources_not_encrypted.yml",
            [
                Failure(
                    granularity=RuleGranularity.RESOURCE,
                    reason="The database some-name does not seem to be encrypted. Database resources should be "
                    "encrypted and have the property StorageEncrypted set to True.",
                    risk_value=RuleRisk.LOW,
                    rule="StorageEncryptedRule",
                    rule_mode=RuleMode.DEBUG,
                    actions=None,
                    resource_ids=None,
                    resource_types={"AWS::RDS::DBInstance"},
                ),
                Failure(
                    granularity=RuleGranularity.RESOURCE,
                    reason="The database some-name-backup does not seem to be encrypted. Database resources should be "
                    "encrypted and have the property StorageEncrypted set to True.",
                    risk_value=RuleRisk.LOW,
                    rule="StorageEncryptedRule",
                    rule_mode=RuleMode.DEBUG,
                    actions=None,
                    resource_ids=None,
                    resource_types={"AWS::RDS::DBInstance"},
                ),
            ],
        ),
        (
            "rules/StorageEncryptedRule/no_db_resource.yml",
            [],
        ),
    ],
)
def test_add_failure_if_db_resource_not_encrypted(template, failures):
    rule = StorageEncryptedRule(None)
    model = get_cfmodel_from(template)
    resolved_model = model.resolve()
    result = rule.invoke(resolved_model)

    assert result.valid
    assert result.failures == failures
