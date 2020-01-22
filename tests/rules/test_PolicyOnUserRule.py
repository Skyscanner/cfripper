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
from pycfmodel.model.cf_model import CFModel
from pytest import fixture

from cfripper.model.result import Result
from cfripper.rules import PolicyOnUserRule
from tests.utils import get_cfmodel_from


@fixture()
def good_template():
    return get_cfmodel_from("rules/PolicyOnUserRule/good_template.json").resolve()


@fixture()
def bad_template():
    return get_cfmodel_from("rules/PolicyOnUserRule/bad_template.json").resolve()


def test_no_failures_are_raised(good_template):
    result = Result()
    rule = PolicyOnUserRule(None, result)
    rule.invoke(good_template)

    assert result.valid
    assert len(result.failed_rules) == 0
    assert len(result.failed_monitored_rules) == 0


def test_failures_are_raised(bad_template: CFModel):
    result = Result()
    rule = PolicyOnUserRule(None, result)
    rule.invoke(bad_template)

    assert result.valid
    assert len(result.failed_rules) == 0
    assert len(result.failed_monitored_rules) == 1
    assert result.failed_monitored_rules[0].rule == "PolicyOnUserRule"
    assert (
        result.failed_monitored_rules[0].reason
        == "IAM policy Policy should not apply directly to users. Should be on group"
    )
