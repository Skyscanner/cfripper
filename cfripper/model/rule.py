from abc import ABC, abstractmethod
from typing import Optional, Set

from cfripper.config.config import Config
from cfripper.model.enums import RuleMode, RuleRisk, RuleGranularity
from cfripper.model.result import Result


class Rule(ABC):
    RULE_MODE = RuleMode.BLOCKING
    RISK_VALUE = RuleRisk.MEDIUM
    GRANULARITY = RuleGranularity.STACK

    def __init__(self, config: Optional[Config], result: Result):
        self._config = config if config else Config()
        self._result = result

    @abstractmethod
    def invoke(self, resources, parameters):
        pass

    def add_failure(
        self,
        rule: str,
        reason: str,
        granularity: Optional[RuleGranularity] = None,
        resource_ids: Optional[Set] = None,
        actions: Optional[Set] = None,
    ):

        if granularity is None:
            granularity = self.GRANULARITY

        self._result.add_failure(
            rule=rule,
            reason=reason,
            rule_mode=self.RULE_MODE,
            risk_value=self.RISK_VALUE,
            resource_ids=resource_ids,
            actions=actions,
            granularity=granularity,
        )

    def add_warning(self, warning):
        self._result.add_warning(warning)
