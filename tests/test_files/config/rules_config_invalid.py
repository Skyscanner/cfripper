from cfripper.config.filter import Filter
from cfripper.config.rule_config import RuleConfig
from cfripper.model.enums import RuleMode

# RULES_CONFIG is here a list of RuleConfig instead of a dict with the rule names as keys
RULES_CONFIG = [
    RuleConfig(
        filters=[
            Filter(
                rule_mode=RuleMode.ALLOWED,
                eval={
                    "and": [
                        {"eq": [{"ref": "config.stack_name"}, "mockstack"]},
                        {"eq": [{"ref": "logical_id"}, "RootRoleOne"]},
                    ]
                },
            )
        ],
    )
]
