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
import pytest
import pycfmodel

from cfripper.model.result import Result
from cfripper.rules.HardcodedRDSPasswordRule import HardcodedRDSPasswordRule


@pytest.fixture()
def bad_template():
    return pycfmodel.parse(
        {
            "Parameters": {
                "Password": {"Type": "String"},
                "Password2": {"Type": "String", "NoEcho": "true"},
                "Password3": {"Type": "String", "NoEcho": "true", "Default": "test"},
            },
            "Resources": {
                "BadDb3": {
                    "Type": "AWS::RDS::DBInstance",
                    "Properties": {
                        "SourceDBInstanceIdentifier": "sampleDbInstance",
                        "MasterUserPassword": {"Ref": "Password"},
                    },
                },
                "BadDb4": {
                    "Type": "AWS::RDS::DBInstance",
                    "Properties": {
                        "SourceDBInstanceIdentifier": "sampleDbInstance",
                        "MasterUserPassword": {"Ref": "Password2"},
                    },
                },
                "BadDb5": {
                    "Type": "AWS::RDS::DBInstance",
                    "Properties": {
                        "SourceDBInstanceIdentifier": "sampleDbInstance",
                        "MasterUserPassword": {"Ref": "Password3"},
                    },
                },
            },
        }
    ).resolve()


def test_failures_are_raised(bad_template):
    result = Result()
    rule = HardcodedRDSPasswordRule(None, result)

    rule.invoke(bad_template)

    assert not result.valid
    assert len(result.failed_rules) == 2
    assert len(result.failed_monitored_rules) == 0
    assert result.failed_rules[0]["reason"] == "Default RDS password parameter or missing NoEcho for BadDb3."
    assert result.failed_rules[1]["reason"] == "Default RDS password parameter or missing NoEcho for BadDb5."
