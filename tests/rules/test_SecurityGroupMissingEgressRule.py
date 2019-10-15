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
import pytest

from cfripper.rules.SecurityGroupMissingEgressRule import SecurityGroupMissingEgressRule
from cfripper.model.result import Result
from tests.utils import get_cfmodel_from


@pytest.fixture()
def single_security_group_one_cidr_ingress():
    return get_cfmodel_from(
        "rules/SecurityGroupMissingEgressRule/single_security_group_one_cidr_ingress.json"
    ).resolve()


def test_single_security_group_one_cidr_ingress(single_security_group_one_cidr_ingress):
    result = Result()
    rule = SecurityGroupMissingEgressRule(None, result)
    rule.invoke(single_security_group_one_cidr_ingress)

    assert result.valid
    assert len(result.failed_rules) == 0
    assert len(result.failed_monitored_rules) == 1
    assert result.failed_monitored_rules[0]["rule"] == "SecurityGroupMissingEgressRule"
    assert (
        result.failed_monitored_rules[0]["reason"]
        == "Missing egress rule in sg means all traffic is allowed outbound. Make this explicit if it is desired configuration"
    )


test_single_security_group_one_cidr_ingress(single_security_group_one_cidr_ingress())
