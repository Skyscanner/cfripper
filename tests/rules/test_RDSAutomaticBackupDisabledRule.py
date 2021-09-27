from unittest.mock import patch

import pytest

from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rules.rds_automatic_backup_disabled import RDSAutomaticBackupDisabledRule
from tests.utils import get_cfmodel_from


@pytest.mark.parametrize(
    "template_path", ["good_template_cluster.yaml", "good_template_instance.yaml", "not_defined_in_template.yaml"],
)
def test_rds_auto_backup_disabled_valid_happy_path(template_path):
    rule = RDSAutomaticBackupDisabledRule(None)
    model = get_cfmodel_from(f"rules/RDSAutomaticBackupDisabledRule/{template_path}").resolve()
    result = rule.invoke(model)
    assert result.valid


@patch("logging.Logger.warning")
def test_rds_auto_backup_disabled_not_integer(mock_warning_logger):
    rule = RDSAutomaticBackupDisabledRule(None)
    model = get_cfmodel_from("rules/RDSAutomaticBackupDisabledRule/not_integer_skip_template.yaml").resolve()
    result = rule.invoke(model)
    assert result.valid
    mock_warning_logger.assert_called_once_with(
        "Could not convert backup retention period property of MyRDS to an integer: 14.5."
    )


@pytest.mark.parametrize(
    "template_path, type",
    [("bad_template_cluster.yaml", "AWS::RDS::DBCluster"), ("bad_template_instance.yaml", "AWS::RDS::DBInstance")],
)
def test_rds_auto_backup_disabled_invalid(template_path, type):
    rule = RDSAutomaticBackupDisabledRule(None)
    model = get_cfmodel_from(f"rules/RDSAutomaticBackupDisabledRule/{template_path}").resolve()
    result = rule.invoke(model)
    assert not result.valid
    assert result.failures == [
        Failure(
            granularity=RuleGranularity.RESOURCE,
            reason=(
                f"The {type} MyRDS has automatic backups disabled. "
                f"There is a risk of loss of data in the event of a disaster or deletion of the {type}."
            ),
            risk_value=RuleRisk.MEDIUM,
            rule="RDSAutomaticBackupDisabledRule",
            rule_mode=RuleMode.BLOCKING,
            actions=None,
            resource_ids={"MyRDS"},
        )
    ]
