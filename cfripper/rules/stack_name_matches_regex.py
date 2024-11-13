from typing import Dict, Optional

from pycfmodel.model.cf_model import CFModel

from cfripper.config.regex import REGEX_ALPHANUMERICAL_OR_HYPHEN
from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Result
from cfripper.rules.base_rules import Rule


class StackNameMatchesRegexRule(Rule):
    """
    Checks that a given stack follows the naming convention given by a regex. For this to work,
    the stack name must be given either in the config or in the extras using the key
    "stack_name".
    """

    RULE_MODE = RuleMode.DEBUG  # for demonstration purposes
    RISK_VALUE = RuleRisk.LOW
    GRANULARITY = RuleGranularity.STACK
    REASON = "The stack name {} does not follow the naming convention, reason: {}"
    REGEX = REGEX_ALPHANUMERICAL_OR_HYPHEN
    REGEX_REASON = "Only alphanumerical characters and hyphens allowed."

    def _stack_name_matches_regex(self, stack_name: str) -> bool:
        """Check that stack name follows naming convention."""
        return bool(self.REGEX.match(stack_name))

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()
        if not extras:
            extras = {}
        stack_name = self._config.stack_name or extras.get("stack_name", "")
        if not stack_name:
            return result

        if not self._stack_name_matches_regex(stack_name):
            self.add_failure_to_result(
                result,
                self.REASON.format(stack_name, self.REGEX_REASON),
                self.GRANULARITY,
                risk_value=self.RISK_VALUE,
                context={"config": self._config, "extras": extras},
            )
        return result
