from abc import ABC, abstractmethod
from typing import Optional

from cfripper.config.config import Config
from cfripper.model.enums import RuleMode, RuleRisk
from cfripper.model.result import Result


class Rule(ABC):
    RULE_MODE = RuleMode.BLOCKING
    RISK_VALUE = RuleRisk.MEDIUM

    def __init__(self, config: Optional[Config], result: Result):
        self._config = config if config else Config()
        self._result = result

    @abstractmethod
    def invoke(self, resources, parameters):
        pass

    def add_failure(self, rule: str, reason: str):

        self._result.add_failure(
            rule=rule,
            reason=reason,
            rule_mode=self.RULE_MODE,
            risk_value=self.RISK_VALUE,
        )

    def add_warning(self, warning):
        self._result.add_warning(warning)
