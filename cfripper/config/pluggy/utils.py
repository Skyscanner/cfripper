from pluggy import PluginManager

from cfripper import rules
from cfripper.config.pluggy import hookspec


def get_plugin_manager():
    pm = PluginManager("cfripper")
    pm.add_hookspecs(hookspec)
    pm.load_setuptools_entrypoints("cfripper")  # Dynamically load plugins using entry points
    pm.register(rules)  # Register default rules
    return pm


def get_all_rules():
    pm = get_plugin_manager()
    plugins_output = pm.hook.cfripper_get_rules()
    rules = {k: v for d in plugins_output for k, v in d.items()}
    return rules
