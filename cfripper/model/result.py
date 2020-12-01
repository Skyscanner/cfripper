from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Extra

from cfripper.model.enums import RuleMode


class Failure(BaseModel):
    granularity: str
    reason: str
    risk_value: str
    rule: str
    rule_mode: str
    actions: Optional[set] = set()
    resource_ids: Optional[set] = set()

    class Config(BaseModel.Config):
        extra = Extra.forbid

    def serializable(self):
        return {
            "rule": self.rule,
            "reason": self.reason,
            "rule_mode": self.rule_mode,
            "risk_value": self.risk_value,
            "resource_ids": sorted(self.resource_ids or []),
            "actions": sorted(self.actions or []),
            "granularity": self.granularity,
        }


class Result(BaseModel):
    class Config(BaseModel.Config):
        extra = Extra.forbid

    failed_rules: List[Failure] = []
    exceptions: List = []
    failed_monitored_rules: List[Failure] = []
    warnings: List[Failure] = []

    # Temporary fix until https://github.com/samuelcolvin/pydantic/issues/935 is fixed
    @classmethod
    def get_properties(cls):
        return [prop for prop in cls.__dict__ if isinstance(cls.__dict__[prop], property)]

    def dict(
        self,
        *,
        include: Union["AbstractSetIntStr", "DictIntStrAny"] = None,  # noqa: F821
        exclude: Union["AbstractSetIntStr", "DictIntStrAny"] = None,  # noqa: F821
        by_alias: bool = False,
        skip_defaults: bool = None,
        exclude_unset: bool = False,
        exclude_defaults: bool = False,
        exclude_none: bool = False,
    ) -> Dict[str, Any]:
        """Override the dict function to include our properties"""
        attribs = super().dict(
            include=include,
            exclude=exclude,
            by_alias=by_alias,
            skip_defaults=skip_defaults,
            exclude_unset=exclude_unset,
            exclude_defaults=exclude_defaults,
            exclude_none=exclude_none,
        )
        props = self.get_properties()

        # Include and exclude properties
        if include:
            props = [prop for prop in props if prop in include]
        if exclude:
            props = [prop for prop in props if prop not in exclude]

        # Update the attribute dict with the properties
        if props:
            attribs.update({prop: getattr(self, prop) for prop in props})
        return attribs

    def __repr_args__(self):
        return self.dict().items()  # type: ignore

    # End of temporary fix

    def add_failure(
        self, rule: str, reason: str, rule_mode: str, risk_value: str, granularity: str, resource_ids=None, actions=None
    ):

        if resource_ids is None:
            resource_ids = set()

        if actions is None:
            actions = set()

        failure = Failure(
            rule=rule,
            reason=reason,
            rule_mode=rule_mode,
            risk_value=risk_value,
            resource_ids=resource_ids,
            actions=actions,
            granularity=granularity,
        )

        if rule_mode is not RuleMode.BLOCKING:
            self.add_failure_monitored_rule(failure=failure)
            return

        self.add_failure_blocking_rule(failure=failure)

    def add_exception(self, ex):
        self.exceptions.append(ex)

    def add_warning(self, warning: Failure):
        self.warnings.append(warning)

    def add_failure_monitored_rule(self, failure: Failure):
        self.failed_monitored_rules.append(failure)

    def add_failure_blocking_rule(self, failure: Failure):
        self.failed_rules.append(failure)

    @property
    def valid(self) -> bool:
        return not bool([rule for rule in self.failed_rules if rule.rule_mode == RuleMode.BLOCKING])

    def __add__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented

        return Result(
            failed_rules=self.failed_rules + other.failed_rules,
            exceptions=self.exceptions + other.exceptions,
            failed_monitored_rules=self.failed_monitored_rules + other.failed_monitored_rules,
            warnings=self.warnings + other.warnings,
        )
