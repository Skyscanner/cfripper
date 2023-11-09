import re
from typing import Dict, Optional

from pycfmodel.model.cf_model import CFModel

from cfripper.config.regex import REGEX_ALPHANUMERICAL_OR_HYPHEN
from cfripper.model.enums import RuleMode, RuleRisk
from cfripper.model.result import Result
from cfripper.rules.base_rules import Rule


class StackNameMatchesRegexRule(Rule):
    """
    Checks that a given stack follows the naming convention given by a regex.
    """

    RULE_MODE = RuleMode.DEBUG
    RISK_VALUE = RuleRisk.LOW
    REASON = (
        "The stack name {} does not follow the naming convention (only alphanumerical characters and hyphens allowed)."
    )

    def _stack_name_matches_regex(self, stack_name: str) -> bool:
        """Check that stack name follows naming convention."""
        return bool(REGEX_ALPHANUMERICAL_OR_HYPHEN.match(stack_name))

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()
        stack_name = self._config.stack_name
        if not stack_name:
            return result
        if not extras:
            extras = {}

        if not self._stack_name_matches_regex(stack_name):
            self.add_failure_to_result(
                result,
                self.REASON.format(stack_name),
                context={"config": self._config, "extras": extras},
            )
        return result
