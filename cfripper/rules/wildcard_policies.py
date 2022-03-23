__all__ = [
    "GenericWildcardPolicyRule",
    "GenericResourceWildcardPolicyRule",
    "S3BucketPolicyWildcardActionRule",
    "SNSTopicPolicyWildcardActionRule",
    "SQSQueuePolicyWildcardActionRule",
]
import logging
from typing import Dict, Optional, Type

from pycfmodel.model.cf_model import CFModel
from pycfmodel.model.resources.resource import Resource
from pycfmodel.model.resources.s3_bucket_policy import S3BucketPolicy
from pycfmodel.model.resources.sns_topic_policy import SNSTopicPolicy
from pycfmodel.model.resources.sqs_queue_policy import SQSQueuePolicy

from cfripper.config.regex import REGEX_HAS_STAR_OR_STAR_AFTER_COLON
from cfripper.model.enums import RuleGranularity
from cfripper.model.result import Result
from cfripper.rules.base_rules import Rule

logger = logging.getLogger(__file__)


class GenericWildcardPolicyRule(Rule):
    """
    Abstract rule that checks for use of the wildcard `*` character in Actions of Policy Documents of AWS Resources.
    This rule must be inherited by another class to be used, with `AWS_RESOURCE` set to the resource to be checked.
    See `S3BucketPolicyWildcardActionRule` and `SQSQueuePolicyWildcardActionRule` for examples.
    """

    REASON = "The {} {} should not allow a `*` action"

    GRANULARITY = RuleGranularity.RESOURCE

    AWS_RESOURCE: Type[Resource] = None

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()
        if self.AWS_RESOURCE is None:
            logger.warning(f"Not running {type(self).__name__} rule as AWS_RESOURCE is not defined.")
        else:
            for logical_id, resource in cfmodel.Resources.items():
                if isinstance(resource, self.AWS_RESOURCE) and resource.Properties.PolicyDocument.allowed_actions_with(
                    REGEX_HAS_STAR_OR_STAR_AFTER_COLON
                ):
                    self.add_failure_to_result(
                        result,
                        self.REASON.format(self.AWS_RESOURCE.__name__, logical_id),
                        resource_ids={logical_id},
                        context={
                            "config": self._config,
                            "extras": extras,
                            "logical_id": logical_id,
                            "resource": resource,
                        },
                        resource_types={resource.Type},
                    )
        return result


class GenericResourceWildcardPolicyRule(GenericWildcardPolicyRule):
    """
    Rule that checks for use of the wildcard `*` character in Actions of Policy Documents of Generic AWS Resources.
    """

    REASON = "{} should not allow a `*` action"
    GRANULARITY = RuleGranularity.RESOURCE

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()
        for logical_id, resource in cfmodel.Resources.items():
            policy_documents = resource.policy_documents
            if policy_documents:
                for document in policy_documents:
                    if document.policy_document.allowed_actions_with(REGEX_HAS_STAR_OR_STAR_AFTER_COLON):
                        self.add_failure_to_result(
                            result,
                            self.REASON.format(logical_id),
                            resource_ids={logical_id},
                            context={
                                "config": self._config,
                                "extras": extras,
                                "logical_id": logical_id,
                                "resource": resource,
                            },
                            resource_types={resource.Type},
                        )
        return result


class S3BucketPolicyWildcardActionRule(GenericWildcardPolicyRule):
    """
    Soon to be replaced by `GenericResourceWildcardPolicyRule`.

    Checks for use of the wildcard `*` character in the Actions of Policy Documents of S3 Bucket Policies.
    This rule is a subclass of `GenericWildcardPolicyRule`.

    Filters context:
        | Parameter               | Type                             | Description                                                    |
        |:-----------------------:|:--------------------------------:|:--------------------------------------------------------------:|
        |`config`                 | str                              | `config` variable available inside the rule                    |
        |`extras`                 | str                              | `extras` variable available inside the rule                    |
        |`logical_id`             | str                              | ID used in Cloudformation to refer the resource being analysed |
        |`resource`               | `S3BucketPolicy`                 | Resource that is being addressed                               |
    """

    AWS_RESOURCE = S3BucketPolicy


class SNSTopicPolicyWildcardActionRule(GenericWildcardPolicyRule):
    """
    Soon to be replaced by `GenericResourceWildcardPolicyRule`.

    Checks for use of the wildcard `*` character in the Actions of Policy Documents of SQS Queue Policies.
    This rule is a subclass of `GenericWildcardPolicyRule`.

    Filters context:
        | Parameter               | Type                             | Description                                                    |
        |:-----------------------:|:--------------------------------:|:--------------------------------------------------------------:|
        |`config`                 | str                              | `config` variable available inside the rule                    |
        |`extras`                 | str                              | `extras` variable available inside the rule                    |
        |`logical_id`             | str                              | ID used in Cloudformation to refer the resource being analysed |
        |`resource`               | `SNSTopicPolicy`                 | Resource that is being addressed                               |
    """

    AWS_RESOURCE = SNSTopicPolicy


class SQSQueuePolicyWildcardActionRule(GenericWildcardPolicyRule):
    """
    Soon to be replaced by `GenericResourceWildcardPolicyRule`.

    Checks for use of the wildcard `*` character in the Actions of Policy Documents of SQS Queue Policies.
    This rule is a subclass of `GenericWildcardPolicyRule`.

    Filters context:
        | Parameter               | Type                             | Description                                                    |
        |:-----------------------:|:--------------------------------:|:--------------------------------------------------------------:|
        |`config`                 | str                              | `config` variable available inside the rule                    |
        |`extras`                 | str                              | `extras` variable available inside the rule                    |
        |`logical_id`             | str                              | ID used in Cloudformation to refer the resource being analysed |
        |`resource`               | `SQSQueuePolicy`                 | Resource that is being addressed                               |
    """

    AWS_RESOURCE = SQSQueuePolicy
