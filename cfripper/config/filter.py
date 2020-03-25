import operator
import re
from functools import reduce
from typing import Any, Callable, Dict, List, Optional, Union

from pycfmodel.model.resources.iam_role import IAMRole
from pydantic import BaseModel, validator

from cfripper.model.enums import RuleMode, RuleRisk
from pydash.objects import get
IMPLEMENTED_FILTER_FUNCTIONS = {
    "eq": lambda *args, **kwargs: operator.eq(*args),
    "ne": lambda *args, **kwargs: operator.ne(*args),
    "lt": lambda *args, **kwargs: operator.lt(*args),
    "gt": lambda *args, **kwargs: operator.gt(*args),
    "le": lambda *args, **kwargs: operator.le(*args),
    "ge": lambda *args, **kwargs: operator.ge(*args),
    "not": lambda *args, **kwargs: operator.not_(*args),
    "or": lambda *args, **kwargs: any(args),
    "and": lambda *args, **kwargs: all(args),
    "in": lambda a, b, *args, **kwargs: operator.contains(b, a),
    "regex": lambda *args, **kwargs: bool(re.match(*args)),
    "ref": lambda param_name, *args, **kwargs: get(kwargs, param_name),
}


def is_resolvable_dict(value: Any) -> bool:
    return isinstance(value, dict) and len(value) == 1 and next(iter(value)) in IMPLEMENTED_FILTER_FUNCTIONS


def build_evaluator(tree: Union[str, int, float, bool, List, Dict]) -> Callable:
    if is_resolvable_dict(tree):
        function_name, nodes = list(tree.items())[0]
        if not isinstance(nodes, list):
            nodes = [nodes]
        nodes = [build_evaluator(node) for node in nodes]
        function_resolver = IMPLEMENTED_FILTER_FUNCTIONS[function_name]
        return lambda kwargs: function_resolver(*[node(kwargs) for node in nodes], **kwargs)

    return lambda kwargs: tree


class Filter(BaseModel):
    reason: str = ""
    eval: Union[Dict, Callable]
    rule_mode: Optional[RuleMode] = None
    risk_value: Optional[RuleRisk] = None

    @validator("eval", pre=True)
    def set_eval(cls, eval):
        return build_evaluator(eval)

    def __call__(self, **kwargs):
        return self.eval(kwargs)


filter = Filter(
    rule_mode=RuleMode.DISABLED,
    eval={
        "and": [
            {"regex": ["^alc-db-.*$", {"ref": "resource.Properties.RoleName"}]},
            {"eq": [{"ref": "principal"}, "arn:aws:iam::512406415041:role/databricks-assuming-role"]},
        ]
    },
)

assert filter(
    resource=IAMRole(
        **{
            "Type": "AWS::IAM::Role",
            "Properties": {
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": {
                        "Effect": "Allow",
                        "Principal": {"Service": ["ec2.amazonaws.com"], "AWS": "arn:aws:iam::111111111111:root"},
                        "Action": ["sts:AssumeRole"],
                    },
                },
                "Path": "/",
                "Policies": [
                    {
                        "PolicyName": "root",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"},
                        },
                    }
                ],
                "ManagedPolicyArns": ["arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"],
                "RoleName": "alc-db-test",
            },
        }
    ),
    principal="arn:aws:iam::512406415041:role/databricks-assuming-role",
)
