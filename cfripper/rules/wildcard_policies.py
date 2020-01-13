"""
Copyright 2018-2019 Skyscanner Ltd

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
"""
__all__ = ["GenericWildcardPolicyRule", "S3BucketPolicyWildcardActionRule", "SQSQueuePolicyWildcardActionRule"]
import logging

from pycfmodel.model.resources.s3_bucket_policy import S3BucketPolicy
from pycfmodel.model.resources.sqs_queue_policy import SQSQueuePolicy

from cfripper.config.regex import REGEX_HAS_STAR_OR_STAR_AFTER_COLON
from cfripper.model.enums import RuleGranularity, RuleMode
from cfripper.rules.base_rules import Rule

logger = logging.getLogger(__file__)


class GenericWildcardPolicyRule(Rule):
    """
    Abstract rule that checks for use of the wildcard `*` character in Actions of Policy Documents of AWS Resources.
    """

    REASON = "The {} {} should not allow a `*` action"

    RULE_MODE = RuleMode.DEBUG
    GRANULARITY = RuleGranularity.RESOURCE

    # this should be of type pycfmodel.model.resources
    AWS_RESOURCE = None

    def invoke(self, cfmodel):
        if not self.AWS_RESOURCE:
            logger.warning(f"Not running {type(self).__name__} rule as AWS_RESOURCE is not defined.")
        else:
            for logical_id, resource in cfmodel.Resources.items():
                if isinstance(resource, self.AWS_RESOURCE) and resource.Properties.PolicyDocument.allowed_actions_with(
                    REGEX_HAS_STAR_OR_STAR_AFTER_COLON
                ):
                    self.add_failure(
                        type(self).__name__,
                        self.REASON.format(self.AWS_RESOURCE.__name__, logical_id),
                        resource_ids={logical_id},
                    )


class S3BucketPolicyWildcardActionRule(GenericWildcardPolicyRule):
    """
    Checks for use of the wildcard `*` character in the Actions of Policy Documents of S3 Bucket Policies.
    """

    AWS_RESOURCE = S3BucketPolicy


class SQSQueuePolicyWildcardActionRule(GenericWildcardPolicyRule):
    """
    Checks for use of the wildcard `*` character in the Actions of Policy Documents of SQS Queue Policies.
    """

    AWS_RESOURCE = SQSQueuePolicy
