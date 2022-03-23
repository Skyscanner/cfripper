import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Set, Tuple, Type

from pycfmodel.model.cf_model import CFModel
from pycfmodel.model.resources.resource import Resource

from cfripper.config.config import Config
from cfripper.config.filter import Filter
from cfripper.config.rule_config import RuleConfig
from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Result

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
    def rule_filters(self) -> List[Filter]:
        return self._config.get_rule_filters(self.__class__.__name__)

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
        resource_types: Optional[Set] = None,
        actions: Optional[Set] = None,
        risk_value: Optional[RuleRisk] = None,
        rule_mode: Optional[RuleMode] = None,
        context: Optional[Dict] = None,
    ):
        rule_mode = rule_mode or self.rule_mode
        risk_value = risk_value or self.risk_value
        granularity = granularity or self.GRANULARITY

        for rule_filter in self.rule_filters:
            try:
                if rule_filter(**context):
                    risk_value = rule_filter.risk_value or risk_value
                    rule_mode = rule_filter.rule_mode or rule_mode
            except Exception:
                logger.exception(f"Exception raised while evaluating filter for `{rule_filter.reason}`", extra=context)

        if rule_mode != RuleMode.ALLOWED:
            result.add_failure(
                rule=type(self).__name__,
                reason=reason,
                rule_mode=rule_mode,
                risk_value=risk_value,
                resource_ids=resource_ids,
                resource_types=resource_types,
                actions=actions,
                granularity=granularity,
            )


class ResourceSpecificRule(Rule):
    """
    Base class for rules that only apply to a subset of resource types.

    RESOURCE_TYPES: Resources to invoke the rule for.
    EXCLUDED_RESOURCE_TYPES: Resources to explicitly not run the rule for.

    Both fields are included to allow for more granular rule definitions. For example,
    you may want to allow all resources except S3BucketPolicies, in which case you
    would define these variables as:

    EXCLUDED_RESOURCE_TYPES = (S3BucketPolicy,)
    RESOURCE_TYPES = (Resource,)

    Where the `S3BucketPolicy` Resource inherits from the base `Resource` class.
    """

    EXCLUDED_RESOURCE_TYPES: Tuple[Type] = tuple()
    RESOURCE_TYPES: Tuple[Type] = tuple()

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, self.RESOURCE_TYPES) and not isinstance(resource, self.EXCLUDED_RESOURCE_TYPES):
                result += self.resource_invoke(resource=resource, logical_id=logical_id, extras=extras)
        return result

    @abstractmethod
    def resource_invoke(self, resource: Resource, logical_id: str, extras: Optional[Dict] = None) -> Result:
        pass


class PrincipalCheckingRule(Rule, ABC):
    """
    Abstract class for rules that check principals.

    `valid_principals` is a set of the following Account IDs and Canonical IDs:
      - `aws_principals` set in the user defined config (default = None)
      - ELB Log Account IDs from AWS
      - ElastiCache Backup Canonical IDs
      - (if defined) The AWS Account in the config which CFRipper is executing with

    When using `valid_principals`, make sure the scope of accounts allowed is not too large.
    It might be the case that the account the stack is being deployed in is in this set.
    This could raise false negatives in rules. If a rule should only be exempt for AWS Service
    IDs, such as ELB and ElastiCache, consider using `_get_allowed_from_config()` directly.
    """

    _valid_principals = None

    def _get_allowed_from_config(self, services: List[str] = None) -> Set[str]:
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
                *self._get_allowed_from_config(),
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
        """
        This is designed to be overwritten as a class variable
        """
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
                    resource_types={resource.Type},
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
