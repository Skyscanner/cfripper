import re
from typing import Any, Callable, Dict, List, Optional, Set, Union

from pydantic import BaseModel, validator
from pydash.objects import get

from cfripper.config.filter_debug_functions import IMPLEMENTED_FILTER_FUNCTIONS_DEBUG
from cfripper.model.enums import RuleMode, RuleRisk


def param_resolver(f):
    def wrap(*args, **kwargs):
        return f(*(arg(kwargs) for arg in args), **kwargs)

    return wrap


IMPLEMENTED_FILTER_FUNCTIONS = {
    "eq": param_resolver(lambda a, b, **kwargs: a == b),
    "ne": param_resolver(lambda a, b, **kwargs: a != b),
    "lt": param_resolver(lambda a, b, **kwargs: a < b),
    "gt": param_resolver(lambda a, b, **kwargs: a > b),
    "le": param_resolver(lambda a, b, **kwargs: a <= b),
    "ge": param_resolver(lambda a, b, **kwargs: a >= b),
    "not": param_resolver(lambda a, **kwargs: not a),
    "or": lambda *args, **kwargs: any(arg(kwargs) for arg in args),
    "and": lambda *args, **kwargs: all(arg(kwargs) for arg in args),
    "in": param_resolver(lambda a, b, **kwargs: a in b),
    "regex": param_resolver(lambda *args, **kwargs: bool(re.match(*args))),
    "regex:ignorecase": param_resolver(lambda *args, **kwargs: bool(re.match(*args, re.IGNORECASE))),
    "exists": param_resolver(lambda a, **kwargs: a is not None),
    "empty": param_resolver(lambda *args, **kwargs: len(args) == 0),
    "ref": param_resolver(lambda param_name, **kwargs: get(kwargs, param_name)),
}


def is_resolvable_dict(value: Any, debug: Optional[bool] = False) -> bool:
    filter_functions = IMPLEMENTED_FILTER_FUNCTIONS if not debug else IMPLEMENTED_FILTER_FUNCTIONS_DEBUG
    return isinstance(value, dict) and len(value) == 1 and next(iter(value)) in filter_functions


def build_evaluator(tree: Union[str, int, float, bool, List, Dict], debug: Optional[bool] = False) -> Callable:
    filter_functions = IMPLEMENTED_FILTER_FUNCTIONS if not debug else IMPLEMENTED_FILTER_FUNCTIONS_DEBUG
    if is_resolvable_dict(tree):
        function_name, nodes = list(tree.items())[0]
        if not isinstance(nodes, list):
            nodes = [nodes]
        nodes = [build_evaluator(node) for node in nodes]
        function_resolver = filter_functions[function_name]
        return lambda kwargs: function_resolver(*nodes, **kwargs)

    return lambda kwargs: tree


class Filter(BaseModel):
    debug: Optional[bool] = False
    reason: str = ""
    eval: Union[Dict, Callable]
    rule_mode: Optional[RuleMode] = None
    risk_value: Optional[RuleRisk] = None
    rules: Set[str] = None

    @validator("eval", pre=True)
    def set_eval(cls, eval, values):
        return build_evaluator(eval, values["debug"])

    def __call__(self, **kwargs):
        return self.eval(kwargs)
