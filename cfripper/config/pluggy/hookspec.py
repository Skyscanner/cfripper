from typing import Dict

from pluggy import HookspecMarker

from cfripper.rules.base_rules import Rule

hookspec = HookspecMarker("cfripper")


@hookspec
def cfripper_get_rules() -> Dict[str, Rule]:
    pass
