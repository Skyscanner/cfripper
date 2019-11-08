"""
Copyright 2018-2019 Skyscanner Ltd

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
"""
from abc import ABC, abstractmethod
from typing import Optional, Set

from pycfmodel.model.cf_model import CFModel

from ..config.config import Config
from .enums import RuleGranularity, RuleMode, RuleRisk
from .result import Result


class Rule(ABC):
    RULE_MODE = RuleMode.BLOCKING
    RISK_VALUE = RuleRisk.MEDIUM
    GRANULARITY = RuleGranularity.STACK

    def __init__(self, config: Optional[Config], result: Result):
        self._config = config if config else Config()
        self._result = result

    @abstractmethod
    def invoke(self, cfmodel: CFModel):
        pass

    def add_failure(
        self,
        rule: str,
        reason: str,
        granularity: Optional[RuleGranularity] = None,
        resource_ids: Optional[Set] = None,
        actions: Optional[Set] = None,
        risk_value: Optional[RuleRisk] = None,
        rule_mode: Optional[RuleMode] = None,
    ):
        self._result.add_failure(
            rule=rule,
            reason=reason,
            rule_mode=rule_mode or self.RULE_MODE,
            risk_value=risk_value or self.RISK_VALUE,
            resource_ids=resource_ids,
            actions=actions,
            granularity=granularity or self.GRANULARITY,
        )

    def add_warning(self, warning):
        self._result.add_warning(warning)
