from pluggy import HookspecMarker

hookspec = HookspecMarker("cfripper")


@hookspec
def cfripper_get_rules():
    pass
