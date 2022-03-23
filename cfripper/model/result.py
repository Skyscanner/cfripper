from typing import Collection, List, Optional

from pydantic import BaseModel, Extra

from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk


class Failure(BaseModel):
    granularity: RuleGranularity
    reason: str
    risk_value: RuleRisk
    rule: str
    rule_mode: RuleMode
    actions: Optional[set] = set()
    resource_ids: Optional[set] = set()
    resource_types: Optional[set] = set()

    class Config(BaseModel.Config):
        extra = Extra.forbid

    def serializable(self):
        return {
            "rule": self.rule,
            "reason": self.reason,
            "rule_mode": self.rule_mode,
            "risk_value": self.risk_value,
            "resource_ids": sorted(self.resource_ids or []),
            "resource_types": sorted(self.resource_types or []),
            "actions": sorted(self.actions or []),
            "granularity": self.granularity,
        }


class Result(BaseModel):
    class Config(BaseModel.Config):
        extra = Extra.forbid
        arbitrary_types_allowed = True

    exceptions: List[Exception] = []
    failures: List[Failure] = []

    def get_failures(
        self,
        include_rule_modes: Optional[Collection[RuleMode]] = None,
        exclude_rule_modes: Optional[Collection[RuleMode]] = None,
    ) -> List[Failure]:
        result = []
        for failure in self.failures:
            if (not exclude_rule_modes or failure.rule_mode not in exclude_rule_modes) and (
                not include_rule_modes or failure.rule_mode in include_rule_modes
            ):
                result.append(failure)
        return result

    def add_exception(self, ex: Exception):
        self.exceptions.append(ex)

    def add_failure(
        self,
        rule: str,
        reason: str,
        rule_mode: RuleMode,
        risk_value: RuleRisk,
        granularity: RuleGranularity,
        resource_ids=None,
        resource_types=None,
        actions=None,
    ):
        self.failures.append(
            Failure(
                rule=rule,
                reason=reason,
                rule_mode=rule_mode,
                risk_value=risk_value,
                resource_ids=resource_ids,
                resource_types=resource_types,
                actions=actions,
                granularity=granularity,
            )
        )

    @property
    def valid(self) -> bool:
        return not any(failure for failure in self.failures if failure.rule_mode == RuleMode.BLOCKING)

    def __add__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented

        return Result(exceptions=self.exceptions + other.exceptions, failures=self.failures + other.failures)
