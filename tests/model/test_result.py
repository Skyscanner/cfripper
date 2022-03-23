from typing import List, Set, Tuple

import pytest

from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure, Result
from tests.utils import compare_lists_of_failures


def test_result_valid_after_removing_failures():
    result = Result()
    result.add_failure(
        rule="mock_rule",
        reason="mock_reason",
        rule_mode=RuleMode.BLOCKING,
        risk_value=RuleRisk.HIGH,
        granularity=RuleGranularity.STACK,
    )
    # Result has a blocking failure, so it should be invalid
    assert result.valid is False

    result.failures = []
    # Result has no failures, so it should be valid
    assert result.valid is True


def test_result_addition():
    failure1 = Failure(
        granularity=RuleGranularity.STACK,
        reason="reason1",
        risk_value=RuleRisk.HIGH,
        rule="rule1",
        rule_mode=RuleMode.BLOCKING,
    )
    failure2 = Failure(
        granularity=RuleGranularity.STACK,
        reason="reason2",
        risk_value=RuleRisk.HIGH,
        rule="rule2",
        rule_mode=RuleMode.BLOCKING,
    )
    result1 = Result(failures=[failure1])
    result2 = Result(failures=[failure2])
    assert result1 + result2 == Result(failures=[failure1, failure2])


@pytest.mark.parametrize(
    "failures, include_rule_modes, exclude_rule_modes, expected_result",
    [
        (
            [("A", "A", RuleMode.BLOCKING, RuleRisk.HIGH, RuleGranularity.STACK)],
            set(),
            set(),
            [
                Failure(
                    granularity=RuleGranularity.STACK,
                    reason="A",
                    risk_value=RuleRisk.HIGH,
                    rule="A",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids=None,
                    resource_types=None,
                )
            ],
        ),
        (
            [
                ("A", "A", RuleMode.BLOCKING, RuleRisk.HIGH, RuleGranularity.STACK),
                ("B", "B", RuleMode.MONITOR, RuleRisk.LOW, RuleGranularity.RESOURCE),
            ],
            set(),
            set(),
            [
                Failure(
                    granularity=RuleGranularity.STACK,
                    reason="A",
                    risk_value=RuleRisk.HIGH,
                    rule="A",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids=None,
                    resource_types=None,
                ),
                Failure(
                    granularity=RuleGranularity.RESOURCE,
                    reason="B",
                    risk_value=RuleRisk.LOW,
                    rule="B",
                    rule_mode=RuleMode.MONITOR,
                    actions=None,
                    resource_ids=None,
                    resource_types=None,
                ),
            ],
        ),
        (
            [
                ("A", "A", RuleMode.BLOCKING, RuleRisk.HIGH, RuleGranularity.STACK),
                ("B", "B", RuleMode.MONITOR, RuleRisk.LOW, RuleGranularity.RESOURCE),
            ],
            {RuleMode.MONITOR},
            set(),
            [
                Failure(
                    granularity=RuleGranularity.RESOURCE,
                    reason="B",
                    risk_value=RuleRisk.LOW,
                    rule="B",
                    rule_mode=RuleMode.MONITOR,
                    actions=None,
                    resource_ids=None,
                    resource_types=None,
                )
            ],
        ),
        (
            [
                ("A", "A", RuleMode.BLOCKING, RuleRisk.HIGH, RuleGranularity.STACK),
                ("B", "B", RuleMode.MONITOR, RuleRisk.LOW, RuleGranularity.RESOURCE),
            ],
            set(),
            {RuleMode.MONITOR},
            [
                Failure(
                    granularity=RuleGranularity.STACK,
                    reason="A",
                    risk_value=RuleRisk.HIGH,
                    rule="A",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids=None,
                    resource_types=None,
                ),
            ],
        ),
        (
            [
                ("A", "A", RuleMode.BLOCKING, RuleRisk.HIGH, RuleGranularity.STACK),
                ("B", "B", RuleMode.MONITOR, RuleRisk.LOW, RuleGranularity.RESOURCE),
            ],
            set(),
            {RuleMode.MONITOR},
            [
                Failure(
                    granularity=RuleGranularity.STACK,
                    reason="A",
                    risk_value=RuleRisk.HIGH,
                    rule="A",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids=None,
                    resource_types=None,
                ),
            ],
        ),
        (
            [
                ("A", "A", RuleMode.BLOCKING, RuleRisk.HIGH, RuleGranularity.STACK),
                ("B", "B", RuleMode.MONITOR, RuleRisk.LOW, RuleGranularity.RESOURCE),
            ],
            {RuleMode.MONITOR},
            {RuleMode.MONITOR},
            [],
        ),
        (
            [
                ("A", "A", RuleMode.BLOCKING, RuleRisk.HIGH, RuleGranularity.STACK),
                ("B", "B", RuleMode.MONITOR, RuleRisk.LOW, RuleGranularity.RESOURCE),
            ],
            {RuleMode.MONITOR, RuleMode.BLOCKING},
            {RuleMode.MONITOR},
            [
                Failure(
                    granularity=RuleGranularity.STACK,
                    reason="A",
                    risk_value=RuleRisk.HIGH,
                    rule="A",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids=None,
                    resource_types=None,
                ),
            ],
        ),
    ],
)
def test_get_failures(
    failures: List[Tuple],
    include_rule_modes: Set[RuleMode],
    exclude_rule_modes: Set[RuleMode],
    expected_result: List[Failure],
):
    result = Result()
    for failure in failures:
        result.add_failure(*failure)

    assert compare_lists_of_failures(result.get_failures(include_rule_modes, exclude_rule_modes), expected_result)
