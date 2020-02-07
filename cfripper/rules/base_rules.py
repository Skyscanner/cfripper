"""
Copyright 2018-2020 Skyscanner Ltd

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
"""
import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Set

from pycfmodel.model.cf_model import CFModel

from cfripper.config.config import Config
from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure, Result

logger = logging.getLogger(__file__)


class Rule(ABC):
    RULE_MODE = RuleMode.BLOCKING
    RISK_VALUE = RuleRisk.MEDIUM
    GRANULARITY = RuleGranularity.STACK

    def __init__(self, config: Optional[Config]):
        self._config = config if config else Config()

    @abstractmethod
    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        pass

    def add_failure_to_result(
        self,
        result: Result,
        reason: str,
        granularity: Optional[RuleGranularity] = None,
        resource_ids: Optional[Set] = None,
        actions: Optional[Set] = None,
        risk_value: Optional[RuleRisk] = None,
        rule_mode: Optional[RuleMode] = None,
    ):
        result.add_failure(
            rule=type(self).__name__,
            reason=reason,
            rule_mode=rule_mode or self.RULE_MODE,
            risk_value=risk_value or self.RISK_VALUE,
            resource_ids=resource_ids,
            actions=actions,
            granularity=granularity or self.GRANULARITY,
        )

    def add_warning_to_result(
        self,
        result: Result,
        reason: str,
        granularity: Optional[RuleGranularity] = None,
        resource_ids: Optional[Set] = None,
        actions: Optional[Set] = None,
        risk_value: Optional[RuleRisk] = None,
        rule_mode: Optional[RuleMode] = None,
    ):
        warning = Failure(
            rule=type(self).__name__,
            reason=reason,
            granularity=granularity or self.GRANULARITY,
            resource_ids=resource_ids,
            actions=actions,
            risk_value=risk_value or self.RISK_VALUE,
            rule_mode=rule_mode or self.RULE_MODE,
        )
        result.add_warning(warning)


class PrincipalCheckingRule(Rule):
    """Abstract class for rules that check principals"""

    _valid_principals = None

    def _get_whitelist_from_config(self, services: List[str] = None) -> Set[str]:
        if services is None:
            services = self._config.aws_service_accounts.keys()

        unique_list = set()
        for service in services:
            unique_list |= set(self._config.aws_service_accounts[service])
        return unique_list

    @property
    def valid_principals(self) -> Set[str]:
        if self._valid_principals is None:
            self._valid_principals = {
                *self._config.aws_principals,
                *self._get_whitelist_from_config(),
            }
            if self._config.aws_account_id:
                self._valid_principals.add(self._config.aws_account_id)
        return self._valid_principals
