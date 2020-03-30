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

    result.failed_rules = []
    # Result has no failures, so it should be valid
    assert result.valid is True


def test_result_addition():
    failure1 = Failure(
        granularity=RuleGranularity.STACK, reason="reason1", risk_value="risk1", rule="rule1", rule_mode="mode1",
    )
    failure2 = Failure(
        granularity=RuleGranularity.STACK, reason="reason2", risk_value="risk2", rule="rule2", rule_mode="mode2",
    )
    monitored_failure1 = Failure(
        granularity=RuleGranularity.RESOURCE, reason="reason1", risk_value="risk1", rule="rule1", rule_mode="mode1",
    )
    monitored_failure2 = Failure(
        granularity=RuleGranularity.RESOURCE, reason="reason2", risk_value="risk2", rule="rule2", rule_mode="mode2",
    )
    result1 = Result(failed_rules=[failure1], failed_monitored_rules=[monitored_failure1])
    result2 = Result(failed_rules=[failure2], failed_monitored_rules=[monitored_failure2])
    assert result1 + result2 == Result(
        failed_rules=[failure1, failure2], failed_monitored_rules=[monitored_failure1, monitored_failure2]
    )
