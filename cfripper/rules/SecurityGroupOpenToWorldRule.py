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


from cfripper.config.logger import get_logger
from cfripper.model.rule_processor import Rule

logger = get_logger()


class SecurityGroupOpenToWorldRule(Rule):

    def invoke(self, resources, parameters):
        rs = resources.get("AWS::EC2::SecurityGroup", [])
        for resource in rs:
            self.process_resource(resource.logical_id, resource)

    def process_resource(self, logical_name, properties):
        if not properties:
            return

        for ingress in properties.security_group_ingress:
            if ingress.ipv4_slash_zero() or ingress.ipv6_slash_zero():
                self.check_ports(logical_name, ingress)

    def check_ports(self, logical_name, ingress_rule):
        from_port = int(ingress_rule.from_port) if ingress_rule.from_port is not None else None
        to_port = int(ingress_rule.to_port) if ingress_rule.from_port is not None else None

        if from_port == to_port:
            the_port = from_port
            self.check_single_port(logical_name, the_port)
        else:
            self.check_port_range(logical_name, from_port, to_port)

    def check_single_port(self, logical_name, the_port):
        if str(the_port) not in self._config.ALLOWED_WORLD_OPEN_PORTS:
            reason = "Port {} open to the world in security group \"{}\"".format(
                the_port,
                logical_name,
            )
            self.add_failure(type(self).__name__, reason)

    def check_port_range(self, logical_name, from_port, to_port):
        for port in range(from_port, to_port + 1):
            if str(port) not in self._config.ALLOWED_WORLD_OPEN_PORTS:
                reason = "Ports {} - {} open in Security Group {}".format(
                    from_port,
                    to_port,
                    logical_name,
                )
                self.add_failure(type(self).__name__, reason)
