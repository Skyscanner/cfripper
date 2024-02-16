from typing import Dict, Optional

from pycfmodel.model.cf_model import CFModel

from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Result
from cfripper.rules.base_rules import Rule


class StorageEncryptedRule(Rule):
    RULE_MODE = RuleMode.DEBUG  # for demonstration purposes
    RISK_VALUE = RuleRisk.LOW
    REASON = (
        "The database {} does not seem to be encrypted. Database resources should be encrypted and have the property "
        "StorageEncrypted set to True."
    )
    GRANULARITY = RuleGranularity.RESOURCE

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()

        for resource in cfmodel.Resources.values():
            is_encrypted = getattr(resource.Properties, "StorageEncrypted", False)
            db_name = getattr(resource.Properties, "DBName", "(could not get DB name)")
            if (
                resource.Type == "AWS::RDS::DBInstance"
                and not is_encrypted
                and not getattr(resource.Properties, "Engine", "").startswith(
                    "aurora"
                )  # not applicable for aurora since the encryption for DB instances is managed by the DB cluster
            ):
                self.add_failure_to_result(
                    result,
                    self.REASON.format(db_name),
                    context={"config": self._config, "extras": extras},
                    resource_types={resource.Type},
                )

        return result
