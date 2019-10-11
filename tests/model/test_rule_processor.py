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

from unittest.mock import Mock

from cfripper.model.rule import Rule
from cfripper.model.rule_processor import RuleProcessor
from tests.utils import get_fixture_json


@pytest.fixture()
def template():
    return get_fixture_json("rules/CloudFormationAuthenticationRule/good_template.json")


def test_with_no_rules(template):
    processor = RuleProcessor()
    config = Mock()
    result = Mock()

    processor.process_cf_template(template, config, result)


def test_with_mock_rule(template):
    rule = Mock()

    processor = RuleProcessor(rule)

    config = Mock()
    result = Mock()
    processor.process_cf_template(template, config, result)

    rule.invoke.assert_called()


def test_remove_debug_rules():
    original_failed_monitored_rules = [
        {"rule": "a", "reason": "something", "rule_mode": Rule.MONITOR, "risk_value": Rule.HIGH},
        {"rule": "b", "reason": "something", "rule_mode": Rule.DEBUG, "risk_value": Rule.MEDIUM},
        {"rule": "c", "reason": "something", "rule_mode": Rule.MONITOR, "risk_value": Rule.LOW},
    ]

    list_with_no_debug_rules = [
        {"rule": "a", "reason": "something", "rule_mode": Rule.MONITOR, "risk_value": Rule.HIGH},
        {"rule": "c", "reason": "something", "rule_mode": Rule.MONITOR, "risk_value": Rule.LOW},
    ]

    processed_list = RuleProcessor.remove_debug_rules(rules=original_failed_monitored_rules)
    assert processed_list == list_with_no_debug_rules


def test_remove_debug_rules_no_rules():
    processed_list = RuleProcessor.remove_debug_rules(rules=[])
    assert processed_list == []
