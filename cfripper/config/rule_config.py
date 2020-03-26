from typing import Dict, List, Optional, Union

from pydantic import BaseModel

from cfripper.config.filter import Filter
from cfripper.model.enums import RuleMode, RuleRisk


class RuleConfig(BaseModel):
    rule_mode: Optional[RuleMode] = None
    risk_value: Optional[RuleRisk] = None
    filters: List[Filter] = []


RULE_CONFIGURATIONS: Dict[str, Union[RuleConfig, Dict]] = {}
