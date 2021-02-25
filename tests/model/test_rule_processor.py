from unittest.mock import Mock

import pytest

from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rule_processor import RuleProcessor
from tests.utils import get_fixture_json


@pytest.fixture()
def template():
    return get_fixture_json("rules/CloudFormationAuthenticationRule/cfn_authentication_good.json")


def test_with_mock_rule(template):
    rule = Mock()

    processor = RuleProcessor(rule)

    config = Mock()
    processor.process_cf_template(template, config)

    rule.invoke.assert_called()


def test_remove_debug_rules():
    original_failed_monitored_rules = [
        Failure(
            rule="a",
            reason="something",
            rule_mode=RuleMode.MONITOR,
            granularity=RuleGranularity.STACK,
            risk_value=RuleRisk.HIGH,
        ),
        Failure(
            rule="b",
            reason="something",
            rule_mode=RuleMode.DEBUG,
            granularity=RuleGranularity.STACK,
            risk_value=RuleRisk.MEDIUM,
        ),
        Failure(
            rule="c",
            reason="something",
            rule_mode=RuleMode.MONITOR,
            granularity=RuleGranularity.STACK,
            risk_value=RuleRisk.LOW,
        ),
    ]

    list_with_no_debug_rules = [original_failed_monitored_rules[0], original_failed_monitored_rules[2]]

    processed_list = RuleProcessor.remove_debug_rules(rules=original_failed_monitored_rules)
    assert list_with_no_debug_rules == processed_list


def test_remove_debug_rules_no_rules():
    processed_list = RuleProcessor.remove_debug_rules(rules=[])
    assert [] == processed_list
