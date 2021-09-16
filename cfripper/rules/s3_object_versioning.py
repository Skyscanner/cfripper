__all__ = ["S3ObjectVersioningRule"]

from typing import Dict, Optional

from pycfmodel.model.cf_model import CFModel

from cfripper.model.enums import RuleGranularity, RuleRisk
from cfripper.model.result import Result
from cfripper.rules.base_rules import Rule


class S3ObjectVersioningRule(Rule):
    """
    Checks if the S3 bucket has object versioning enabled or not.

    Risk:
        Not having this property enabled could make the bucket more vulnerable to ransomware attacks.
        Bucket versioning allows the automatic creation of multiple versions of an object.
        When an object is deleted with versioning turned on, it is only marked as deleted but is still retrievable.

    Fix:
        Add `VersioningConfiguration` property with the value `Enabled` to bucket as defined in the
        [AWS documentation](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-versioningconfig.html).

    Code for fix:
        ````yml
        Resources:
          S3Bucket:
            Type: AWS::S3::Bucket
            Properties:
              ...
              VersioningConfiguration:
                Status: Enabled
              ...
        ````

    Filters context:
        | Parameter     | Type               | Description                                                    |
        |:-------------:|:------------------:|:--------------------------------------------------------------:|
        |`config`       | str                | `config` variable available inside the rule                    |
        |`extras`       | str                | `extras` variable available inside the rule                    |
        |`logical_id`   | str                | ID used in Cloudformation to refer the resource being analysed |
        |`resource`     | `S3BucketPolicy`   | Resource that is being addressed                               |
        |`bucket_name`  | str                | Name of the S3 bucket being analysed                           |
    """

    ENABLED_STATUS = "Enabled"
    GRANULARITY = RuleGranularity.RESOURCE
    REASON = "S3 Bucket {} is required to have object versioning enabled"
    RISK_VALUE = RuleRisk.LOW
    SUSPENDED_STATUS = "Suspended"

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()
        for logical_id, resource in cfmodel.resources_filtered_by_type(("AWS::S3::Bucket",)).items():
            if (
                hasattr(resource, "Properties")
                and resource.Properties.get("VersioningConfiguration", {}).get("Status", self.SUSPENDED_STATUS)
                != self.ENABLED_STATUS
            ):
                self.add_failure_to_result(
                    result,
                    self.REASON.format(logical_id),
                    resource_ids={logical_id},
                    context={"config": self._config, "extras": extras, "logical_id": logical_id, "resource": resource},
                )
        return result
