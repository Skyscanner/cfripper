from typing import Optional

from pydantic import BaseModel

from cfripper.model.enums import RuleMode, RuleRisk


class RuleConfig(BaseModel):
    """
    Allows to overwrite the default behaviour of the rule, such as changing the rule mode and risk value.
    Although this config has `None` as default values, `Rule` will use the following values as
    default if no config is given.
    ```
    RULE_MODE = RuleMode.BLOCKING
    RISK_VALUE = RuleRisk.MEDIUM
    ```
    """

    rule_mode: Optional[RuleMode] = None
    risk_value: Optional[RuleRisk] = None
