from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure, Result


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
