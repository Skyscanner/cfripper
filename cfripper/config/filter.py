import logging
import re
from typing import Any, Callable, Dict, List, Optional, Set, Union

from pydantic import BaseModel, validator
from pydash.objects import get

from cfripper.model.enums import RuleMode, RuleRisk

VALID_FUNCTIONS = [
    "eq",
    "ne",
    "lt",
    "gt",
    "le",
    "ge",
    "not",
    "or",
    "and",
    "in",
    "regex",
    "regex:ignorecase",
    "exists",
    "empty",
    "ref",
]

logger = logging.getLogger(__file__)


def get_implemented_filter_function(function_name: str, debug: bool) -> Callable:
    def param_resolver(f):
        def wrap(*args, **kwargs):
            calculated_parameters = [arg(kwargs) for arg in args]
            result = f(*calculated_parameters, **kwargs)
            if debug:
                logger.debug(f"{function_name}({', '.join(str(x) for x in calculated_parameters)}) -> {result}")
            return result

        return wrap

    implemented_filter_functions = {
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
    return implemented_filter_functions[function_name]


def is_resolvable_dict(value: Any) -> bool:
    return isinstance(value, dict) and len(value) == 1 and next(iter(value)) in VALID_FUNCTIONS


def build_evaluator(tree: Union[str, int, float, bool, List, Dict], debug: bool = False) -> Callable:
    if is_resolvable_dict(tree):
        function_name, nodes = list(tree.items())[0]
        if not isinstance(nodes, list):
            nodes = [nodes]
        nodes = [build_evaluator(node, debug) for node in nodes]
        function_resolver = get_implemented_filter_function(function_name, debug)
        return lambda kwargs: function_resolver(*nodes, **kwargs)

    return lambda kwargs: tree


class Filter(BaseModel):
    debug: bool = False
    reason: str = ""
    eval: Union[Dict, Callable]
    rule_mode: Optional[RuleMode] = None
    risk_value: Optional[RuleRisk] = None
    rules: Set[str] = None

    @validator("eval", pre=True)
    def set_eval(cls, eval, values):
        return build_evaluator(eval, values["debug"])

    def __call__(self, **kwargs):
        if self.debug:
            logger.debug(f"Filter: {self.reason}")
        result = self.eval(kwargs)
        if self.debug:
            logger.debug(f"Filter result: {result}")
        return result
