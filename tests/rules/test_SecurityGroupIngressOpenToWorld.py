"""
Copyright 2018-2020 Skyscanner Ltd

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
"""
from pytest import fixture

from cfripper.config.config import Config
from cfripper.rules import SecurityGroupIngressOpenToWorld
from tests.utils import get_cfmodel_from


@fixture()
def bad_template():
    return get_cfmodel_from("rules/SecurityGroupIngressOpenToWorld/bad_template.json").resolve()


def test_failures_are_raised(bad_template):
    rule = SecurityGroupIngressOpenToWorld(Config())
    result = rule.invoke(bad_template)

    assert not result.valid
    assert len(result.failed_rules) == 2
    assert len(result.failed_monitored_rules) == 0
    assert result.failed_rules[0].rule == "SecurityGroupIngressOpenToWorld"
    assert result.failed_rules[0].reason == "Port 46 open to the world in security group 'securityGroupIngress1'"
    assert result.failed_rules[1].rule == "SecurityGroupIngressOpenToWorld"
    assert result.failed_rules[1].reason == "Port 46 open to the world in security group 'securityGroupIngress2'"
