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


"""
This rule will incorrectly block the following stack:
"Metadata": {
        "AWS::CloudFormation::Authentication": {
          "testBasic": {
            "type": "basic",
            "username": {
              "Ref": "MasterUsername"
            },
            "password": {
              "Ref": "MasterUserPassword"
            },
            "uris": ["http://www.example.com/test"]
          }
        }
      }
"""


class CloudFormationAuthenticationRule(Rule):

    REASON = "Possible hardcoded credentials in {}"

    def invoke(self, resources, parameters):
        for name, resource_list in resources.items():
            for resource in resource_list:
                if resource.has_hardcoded_credentials():
                    self.add_failure(type(self).__name__, self.REASON.format(resource.logical_id))
