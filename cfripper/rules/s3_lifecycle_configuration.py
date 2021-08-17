__all__ = ["S3LifecycleConfigurationRule"]

from typing import Dict, Optional

from pycfmodel.model.cf_model import CFModel

from cfripper.model.enums import RuleGranularity, RuleRisk
from cfripper.model.result import Result
from cfripper.rules.base_rules import Rule


class S3LifecycleConfigurationRule(Rule):
    """
    Checks for the presence of `LifecycleConfiguration` on S3 buckets.
    These rules can help with security, compliance, and reduce AWS Costs. The rule does not
    check the specific rules contained with the `LifecycleConfiguration` key.

    Fix:
        Add `LifecycleConfiguration` property to the S3 Bucket as defined in
        https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-lifecycleconfig.html.

    Code for fix:
        An example rule is included within the configuration.

        ````yml
        Resources:
          S3Bucket:
            Type: AWS::S3::Bucket
            Properties:
              ...
              LifecycleConfiguration:
                Rules:
                  - Status: Enabled
                    Prefix: logs/
                    ExpirationInDays: 7
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

    GRANULARITY = RuleGranularity.RESOURCE
    REASON = "S3 Bucket {} is required to contain a LifecycleConfiguration property"
    RISK_VALUE = RuleRisk.LOW

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()
        for logical_id, resource in cfmodel.resources_filtered_by_type(("AWS::S3::Bucket",)).items():
            if hasattr(resource, "Properties") and resource.Properties.get("LifecycleConfiguration") is None:
                self.add_failure_to_result(
                    result,
                    self.REASON.format(logical_id),
                    resource_ids={logical_id},
                    context={"config": self._config, "extras": extras, "logical_id": logical_id, "resource": resource},
                )
        return result
