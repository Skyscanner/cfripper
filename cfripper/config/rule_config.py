from typing import Optional

from pydantic import BaseModel

from cfripper.model.enums import RuleMode, RuleRisk


class RuleConfig(BaseModel):
    rule_mode: Optional[RuleMode] = None
    risk_value: Optional[RuleRisk] = None
