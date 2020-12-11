import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Set, Tuple, Type

from pycfmodel.model.cf_model import CFModel
from pycfmodel.model.resources.resource import Resource

from cfripper.config.config import Config
from cfripper.config.rule_config import RuleConfig
from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure, Result

logger = logging.getLogger(__file__)


class Rule(ABC):
    RULE_MODE = RuleMode.BLOCKING
    RISK_VALUE = RuleRisk.MEDIUM
    GRANULARITY = RuleGranularity.STACK

    def __init__(self, config: Optional[Config]):
        self._config = config if config else Config()

    @property
    def rule_config(self) -> RuleConfig:
        return self._config.get_rule_config(self.__class__.__name__)

    @property
    def rule_mode(self) -> RuleMode:
        return self.rule_config.rule_mode or self.RULE_MODE

    @property
    def risk_value(self) -> RuleRisk:
        return self.rule_config.risk_value or self.RISK_VALUE

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
        context: Optional[Dict] = None,
    ):
        rule_mode = rule_mode or self.rule_mode
        risk_value = risk_value or self.risk_value
        for fltr in self.rule_config.filters:
            try:
                if fltr(**context):
                    risk_value = fltr.risk_value or risk_value
                    rule_mode = fltr.rule_mode or rule_mode
            except Exception:
                logger.exception(f"Exception raised while evaluating filter for `{fltr.reason}`", extra=context)

        if rule_mode not in (RuleMode.DISABLED, RuleMode.WHITELISTED):
            result.add_failure(
                rule=type(self).__name__,
                reason=reason,
                rule_mode=rule_mode,
                risk_value=risk_value,
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
        context: Optional[Dict] = None,
    ):
        rule_mode = rule_mode or self.rule_mode
        risk_value = risk_value or self.risk_value
        for fltr in self.rule_config.filters:
            if fltr(**context):
                risk_value = fltr.risk_value or risk_value
                rule_mode = fltr.rule_mode or rule_mode
        if rule_mode not in (RuleMode.DISABLED, RuleMode.WHITELISTED):
            warning = Failure(
                rule=type(self).__name__,
                reason=reason,
                granularity=granularity or self.GRANULARITY,
                resource_ids=resource_ids,
                actions=actions,
                risk_value=risk_value,
                rule_mode=rule_mode,
            )
            result.add_warning(warning)


class ResourceSpecificRule(Rule):
    """
    Base class for rules that only apply to a subset of resource types
    """

    RESOURCE_TYPES: Tuple[Type] = tuple()

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, self.RESOURCE_TYPES):
                result += self.resource_invoke(resource=resource, logical_id=logical_id, extras=extras)
        return result

    @abstractmethod
    def resource_invoke(self, resource: Resource, logical_id: str, extras: Optional[Dict] = None) -> Result:
        pass


class PrincipalCheckingRule(Rule, ABC):
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


class BaseDangerousPolicyActions(ResourceSpecificRule, ABC):
    """
    Base class for dangerous actions. Admits a DANGEROUS_ACTIONS class variable with a list of dangerous actions
    """

    DEFAULT_FILTERS_CONTEXT = """\
    Filters context:
        | Parameter    | Type             | Description                                                     |
        |:------------:|:----------------:|:---------------------------------------------------------------:|
        |`config`      | str              | `config` variable available inside the rule                     |
        |`extras`      | str              | `extras` variable available inside the rule                     |
        |`logical_id`  | str              | ID used in Cloudformation to refer the resource being analysed  |
        |`policy_name` | `Optional[str]`  | If available, the policy name                                   |
        |`action`      | `List[str]`      | List of dangerous actions contained within the policy           |
    """

    REASON = "Resource {} should not include the following dangerous actions: {}"
    RISK_VALUE = RuleRisk.HIGH
    GRANULARITY = RuleGranularity.ACTION

    @property
    @classmethod
    @abstractmethod
    def DANGEROUS_ACTIONS(cls) -> List[str]:
        # This is designed to be overwritten as a class variable
        raise NotImplementedError

    def resource_invoke(self, resource: Resource, logical_id: str, extras: Optional[Dict] = None) -> Result:
        result = Result()
        for policy in resource.policy_documents:
            actions = policy.policy_document.get_allowed_actions()
            dangerous_actions = set(actions) & set(self.DANGEROUS_ACTIONS)
            if dangerous_actions:
                self.add_failure_to_result(
                    result,
                    self.REASON.format(logical_id, sorted(dangerous_actions)),
                    resource_ids={logical_id},
                    actions=dangerous_actions,
                    context={
                        "config": self._config,
                        "extras": extras,
                        "logical_id": logical_id,
                        "policy_name": policy.name,
                        "actions": sorted(dangerous_actions),
                    },
                )
        return result
