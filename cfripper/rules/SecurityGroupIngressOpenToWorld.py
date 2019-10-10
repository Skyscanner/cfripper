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
from cfripper.rules.SecurityGroupOpenToWorldRule import SecurityGroupOpenToWorldRule


class SecurityGroupIngressOpenToWorld(SecurityGroupOpenToWorldRule):
    def invoke(self, cfmodel):
        for logical_id, resource in cfmodel.Resources.items():
            if resource.Type == "AWS::EC2::SecurityGroupIngress" and (resource.ipv4_slash_zero() or resource.ipv6_slash_zero()):
                for port in range(resource.Properties.FromPort, resource.Properties.ToPort + 1):
                    if str(port) not in self._config.allowed_world_open_ports:
                        self.add_failure(type(self).__name__, self.REASON.format(port, logical_id))

