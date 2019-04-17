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


class HardcodedRDSPasswordRule(Rule):

    REASON = "Default RDS password parameter or missing NoEcho for {}."
    MONITOR_MODE = False

    def invoke(self, resources, parameters):
        for resource in resources.get("AWS::RDS::DBInstance", []):
            if not hasattr(resource, "master_user_password"):
                continue
            if resource.master_user_password:
                self.check_password(
                    resource.master_user_password,
                    parameters,
                    resource,
                )

    def check_password(self, pwd, parameters, resource):
        if isinstance(pwd, dict) and "Ref" in pwd:
            p = self.get_parameter(parameters, pwd["Ref"])
            if not p:
                # That should never happen as it means parameter is missing
                # which is an invalid CF
                # but just in case
                return

            if hasattr(p, "no_echo") and not hasattr(p, "default"):
                return

        self.add_failure(
            type(self).__name__,
            self.REASON.format(resource.logical_id),
        )

    def get_parameter(self, parameters, key):
        for parameter in parameters:
            if parameter.logical_id == key:
                return parameter
        return None
