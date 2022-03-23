__all__ = ["S3LifecycleConfigurationRule"]

from typing import Dict, Optional

from pycfmodel.model.resources.s3_bucket import S3Bucket

from cfripper.model.enums import RuleGranularity, RuleRisk
from cfripper.model.result import Result
from cfripper.rules.base_rules import ResourceSpecificRule


class S3LifecycleConfigurationRule(ResourceSpecificRule):
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
        |`resource`     | `S3Bucket`         | Resource that is being addressed                               |
    """

    GRANULARITY = RuleGranularity.RESOURCE
    REASON = "S3 Bucket {} is required to contain a LifecycleConfiguration property"
    RESOURCE_TYPES = (S3Bucket,)
    RISK_VALUE = RuleRisk.LOW

    def resource_invoke(self, resource: S3Bucket, logical_id: str, extras: Optional[Dict] = None) -> Result:
        result = Result()
        if not resource.Properties.LifecycleConfiguration:
            self.add_failure_to_result(
                result,
                self.REASON.format(logical_id),
                resource_ids={logical_id},
                resource_types={resource.Type},
                context={"config": self._config, "extras": extras, "logical_id": logical_id, "resource": resource},
            )
        return result
