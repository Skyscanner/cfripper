from itertools import chain, combinations

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


ALLOWED_PORTS = [80, 443]


def powerset(iterable):
    # https://docs.python.org/3/library/itertools.html#itertools-recipes
    # powerset([1,2,3]) --> () (1,) (2,) (3,) (1,2) (1,3) (2,3) (1,2,3)
    s = list(iterable)
    return chain.from_iterable(combinations(s, r) for r in range(len(s) + 1))


allow_http_ports_open_to_world_rules_config_filter = Filter(
    reason="It can be acceptable to have Security Groups publicly available on ports 80 or 443.",
    rule_mode=RuleMode.ALLOWED,
    eval={
        "and": [
            {"exists": {"ref": "open_ports"}},
            {
                "or": [
                    {"eq": [list(subset_allowed_ports), {"ref": "open_ports"}]}
                    for subset_allowed_ports in powerset(ALLOWED_PORTS)
                    if subset_allowed_ports
                ]
            },
        ]
    },
    rules={"EC2SecurityGroupOpenToWorldRule", "EC2SecurityGroupIngressOpenToWorldRule"},
)
