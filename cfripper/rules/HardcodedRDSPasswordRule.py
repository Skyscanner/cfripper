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
from pycfmodel.model.parameter import Parameter

from ..model.rule import Rule


class HardcodedRDSPasswordRule(Rule):

    REASON = "Default RDS password parameter or missing NoEcho for {}."

    def invoke(self, cfmodel):
        for logical_id, resource in cfmodel.Resources.items():
            if (
                resource.Type == "AWS::RDS::DBInstance"
                and resource.Properties.get("MasterUserPassword", Parameter.NO_ECHO_NO_DEFAULT)
                != Parameter.NO_ECHO_NO_DEFAULT
            ):
                self.add_failure(type(self).__name__, self.REASON.format(logical_id))
