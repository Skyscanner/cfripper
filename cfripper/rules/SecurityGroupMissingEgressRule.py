"""
Copyright 2018 Skyscanner Ltd

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
"""


from cfripper.model.rule_processor import Rule


class SecurityGroupMissingEgressRule(Rule):

    REASON = "Missing egress rule in {} means all traffic is allowed outbound. Make this explicit if it is desired configuration"
    MONITOR_MODE = True

    def invoke(self, resources, parameters):
        for resource in resources.get("AWS::EC2::SecurityGroup", []):
            if not resource.security_group_egress:
                self.add_failure(
                    type(self).__name__,
                    self.REASON.format(resource.logical_id),
                )
