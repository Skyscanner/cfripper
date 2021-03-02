import logging
import re

from pydash.objects import get

logger = logging.getLogger(__file__)


# Copy of the same function in filter.py to avoid circular dependency
def param_resolver(f):
    def wrap(*args, **kwargs):
        return f(*(arg(kwargs) for arg in args), **kwargs)

    return wrap


def eq(a, b, **kwargs):
    logger.info(f"{a}, {b}")
    return a == b


def ne(a, b, **kwargs):
    logger.info(f"{a}, {b}")
    return a != b


def lt(a, b, **kwargs):
    logger.info(f"{a}, {b}")
    return a < b


def gt(a, b, **kwargs):
    logger.info(f"{a}, {b}")
    return a > b


def le(a, b, **kwargs):
    logger.info(f"{a}, {b}")
    return a <= b


def ge(a, b, **kwargs):
    logger.info(f"{a}, {b}")
    return a >= b


def _not(a, **kwargs):
    logger.info(f"{a}")
    return not a


def _or(*args, **kwargs):
    logger.info(f"{args}")
    return any(arg(kwargs) for arg in args)


def _and(*args, **kwargs):
    logger.info(f"{args}")
    return all(arg(kwargs) for arg in args)


def _in(a, b, **kwargs):
    logger.info(f"{a}, {b}")
    return a in b


def regex(*args, **kwargs):
    logger.info(f"{args}")
    return bool(re.match(*args))


def regex_ignorecase(*args, **kwargs):
    logger.info(f"{args}")
    return bool(re.match(*args, re.IGNORECASE))


def exists(a, **kwargs):
    logger.info(f"{a}")
    return a is not None


def empty(*args, **kwargs):
    logger.info(f"{args}")
    return len(args) == 0


def ref(param_name, **kwargs):
    logger.info(f"{param_name}, {kwargs}")
    return get(kwargs, param_name)


IMPLEMENTED_FILTER_FUNCTIONS_DEBUG = {
    "eq": param_resolver(eq),
    "ne": param_resolver(ne),
    "lt": param_resolver(lt),
    "gt": param_resolver(gt),
    "le": param_resolver(le),
    "ge": param_resolver(ge),
    "not": param_resolver(_not),
    "or": _or,
    "and": _and,
    "in": param_resolver(_in),
    "regex": param_resolver(regex),
    "regex:ignorecase": param_resolver(regex_ignorecase),
    "exists": param_resolver(exists),
    "empty": param_resolver(empty),
    "ref": param_resolver(ref),
}
