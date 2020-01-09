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
__all__ = ["SNSTopicPolicyNotPrincipalRule"]

from pycfmodel.model.resources.sns_topic_policy import SNSTopicPolicy

from cfripper.model.enums import RuleGranularity, RuleMode
from cfripper.model.rule import Rule


class SNSTopicPolicyNotPrincipalRule(Rule):
    """
    Checks if an SNS topic policy has an Allow + a NotPrincipal (exclusive principal).
    """

    GRANULARITY = RuleGranularity.RESOURCE
    REASON = "SNS Topic {} policy should not allow Allow and NotPrincipal at the same time"
    RULE_MODE = RuleMode.MONITOR

    def invoke(self, cfmodel):
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, SNSTopicPolicy):
                for statement in resource.Properties.PolicyDocument._statement_as_list():
                    if statement.NotPrincipal:
                        self.add_failure(type(self).__name__, self.REASON.format(logical_id), resource_ids={logical_id})
