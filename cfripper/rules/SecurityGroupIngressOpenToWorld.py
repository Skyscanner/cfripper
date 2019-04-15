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


from cfripper.rules.SecurityGroupOpenToWorldRule import SecurityGroupOpenToWorldRule


class SecurityGroupIngressOpenToWorld(SecurityGroupOpenToWorldRule):

    def invoke(self, resources, parameters):
        for resource in resources.get("AWS::EC2::SecurityGroupIngress", []):
            self.process_resource(resource.logical_id, resource)

    def process_resource(self, logical_name, ingress):
        if not ingress:
            return

        if ingress.ipv4_slash_zero() or ingress.ipv6_slash_zero():
            self.check_ports(logical_name, ingress)
