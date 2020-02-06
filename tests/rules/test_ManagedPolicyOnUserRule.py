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

from cfripper.rules import ManagedPolicyOnUserRule
from tests.utils import get_cfmodel_from


@fixture()
def good_template():
    return get_cfmodel_from("rules/ManagedPolicyOnUserRule/good_template.json").resolve()


@fixture()
def bad_template():
    return get_cfmodel_from("rules/ManagedPolicyOnUserRule/bad_template.json").resolve()


def test_no_failures_are_raised(good_template):
    rule = ManagedPolicyOnUserRule(None)
    result = rule.invoke(good_template)

    assert result.valid
    assert len(result.failed_rules) == 0
    assert len(result.failed_monitored_rules) == 0


def test_failures_are_raised(bad_template):
    rule = ManagedPolicyOnUserRule(None)
    result = rule.invoke(bad_template)

    assert result.valid
    assert len(result.failed_rules) == 0
    assert len(result.failed_monitored_rules) == 1
    assert result.failed_monitored_rules[0].rule == "ManagedPolicyOnUserRule"
    assert (
        result.failed_monitored_rules[0].reason
        == "IAM managed policy DirectManagedPolicy should not apply directly to users. Should be on group"
    )
