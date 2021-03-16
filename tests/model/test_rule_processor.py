from unittest.mock import Mock

from cfripper.model.enums import RuleMode
from cfripper.rule_processor import RuleProcessor


def test_rule_processor_invoke_rules():
    rule = Mock()
    rule.rule_mode = RuleMode.BLOCKING

    processor = RuleProcessor(rule)

    template = Mock()
    config = Mock()
    processor.process_cf_template(template, config)

    rule.invoke.assert_called()


def test_rule_processor_dont_invoke_disabled_rules():
    rule = Mock()
    rule.rule_mode = RuleMode.DISABLED

    processor = RuleProcessor(rule)

    template = Mock()
    config = Mock()
    processor.process_cf_template(template, config)

    rule.invoke.assert_not_called()
