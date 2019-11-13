from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Result


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
    # Result has no failures, so it should be invalid
    assert result.valid is True
