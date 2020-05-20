__all__ = ["CloudFormationAuthenticationRule"]

from typing import Dict, Optional

from pycfmodel.model.cf_model import CFModel

from cfripper.model.enums import RuleGranularity
from cfripper.model.result import Result
from cfripper.rules.base_rules import Rule


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
    GRANULARITY = RuleGranularity.RESOURCE

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()
        for logical_id, resource in cfmodel.Resources.items():
            if resource.has_hardcoded_credentials():
                self.add_failure_to_result(result, self.REASON.format(logical_id), resource_ids={logical_id})
        return result
