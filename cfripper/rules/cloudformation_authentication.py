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
__all__ = ["CloudFormationAuthenticationRule"]

from cfripper.model.enums import RuleGranularity, RuleMode
from cfripper.model.rule import Rule


class CloudFormationAuthenticationRule(Rule):
    """
    Checks that any `AWS::CloudFormation::Authentication` resource does not contain plain text credentials.

    Risk:
        Secrets are stored in clear text and printed in clear text in the AWS console.

    Fix:
        Do not store credentials in CloudFormation files, use parameters.

    Code for fix:
        ````yml
        Parameters:
          PasswordAuth:
            NoEcho: true
            Description: Some cool password
            MinLength: 8
            Type: String

        ...

        Resources:
          AWS::CloudFormation::Authentication:
            ...
            password:
              Ref: "PasswordAuth"
            ...
        ````
    """

    REASON = "Hardcoded credentials in {}"
    RULE_MODE = RuleMode.MONITOR
    GRANULARITY = RuleGranularity.RESOURCE

    def invoke(self, cfmodel):
        for logical_id, resource in cfmodel.Resources.items():
            if resource.has_hardcoded_credentials():
                self.add_failure(type(self).__name__, self.REASON.format(logical_id), resource_ids={logical_id})
