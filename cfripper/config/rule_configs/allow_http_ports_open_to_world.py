from cfripper.config.filter import Filter
from cfripper.model.enums import RuleMode

"""
To use this Filter, or any Filter, make sure to include it in the `Config` instantiation.

```python
FILTERS = [allow_http_ports_open_to_world_rules_config_filter]

config = Config(
    ...
    rules_filters=FILTERS,
)
```
"""

allow_http_ports_open_to_world_rules_config_filter = Filter(
    reason="It can be acceptable to have Security Groups publicly available on ports 80 or 443.",
    rule_mode=RuleMode.ALLOWED,
    eval={
        "and": [
            {"exists": {"ref": "open_ports"}},
            {"or": [{"in": [80, {"ref": "open_ports"}]}, {"in": [443, {"ref": "open_ports"}]}]},
        ]
    },
    rules={"EC2SecurityGroupOpenToWorldRule", "EC2SecurityGroupIngressOpenToWorldRule"},
)
