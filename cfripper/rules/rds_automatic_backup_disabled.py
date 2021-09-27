__all__ = ["RDSAutomaticBackupDisabledRule"]

import logging
from typing import Dict, Optional

from pycfmodel.model.cf_model import CFModel

from cfripper.model.enums import RuleGranularity
from cfripper.model.result import Result
from cfripper.rules.base_rules import Rule

logger = logging.getLogger(__file__)


class RDSAutomaticBackupDisabledRule(Rule):
    """
    Checks if any RDS clusters or instances have disabled the automatic backup of the database. This
    is done by checking the `BackupRetentionPeriod` property of the instance or cluster definition.
    By default, if this value is not in the template, it is set to 1.
    [More information](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html).

    Risk:
        Disabling automatic backups can result in the loss of data in the case of corruption or deletion of the main
        instance or cluster. The availability of the database will be at risk as well.

    Fix:
        Specifying a non-zero integer value for `BackupRetentionPeriod` (unit is days).

    Code for fix:
        ````yml
        Resources:
          RDSCluster:
            Type: AWS::RDS::DBCluster
            Properties:
              ...
              BackupRetentionPeriod: 7
              ...
        ````

    Filters context:
        | Parameter           | Type                 | Description                                                    |
        |:-------------------:|:--------------------:|:--------------------------------------------------------------:|
        |`config`             | str                  | `config` variable available inside the rule                    |
        |`extras`             | str                  | `extras` variable available inside the rule                    |
        |`logical_id`         | str                  | ID used in Cloudformation to refer the resource being analysed |
        |`resource`           | `Resource`           | Resource that is being addressed                               |
    """

    CF_TEMPLATE_BACKUP_KEY = "BackupRetentionPeriod"
    REASON = (
        "The {} {} has automatic backups disabled. "
        "There is a risk of loss of data in the event of a disaster or deletion of the {}."
    )
    GRANULARITY = RuleGranularity.RESOURCE

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()

        for logical_id, resource in cfmodel.Resources.items():
            if resource.Type == "AWS::RDS::DBCluster" or resource.Type == "AWS::RDS::DBInstance":
                backup_retention_period = resource.Properties.get(self.CF_TEMPLATE_BACKUP_KEY, 1)

                if not isinstance(backup_retention_period, int):
                    try:
                        backup_retention_period = int(backup_retention_period)
                    except Exception:
                        logger.warning(
                            f"Could not convert backup retention period property of {logical_id} to an integer: {backup_retention_period}."
                        )
                        continue

                if backup_retention_period == 0:
                    self.add_failure_to_result(
                        result,
                        self.REASON.format(resource.Type, logical_id, resource.Type),
                        resource_ids={logical_id},
                        context={
                            "config": self._config,
                            "extras": extras,
                            "logical_id": logical_id,
                            "resource": resource,
                        },
                    )

        return result
