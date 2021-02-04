from pluggy import PluginManager

from cfripper import rules
from cfripper.config.pluggy import hookspec


def setup_plugin_manager():
    pm = PluginManager("cfripper")
    pm.add_hookspecs(hookspec)
    return pm


def load_all_plugins(plugin_manager: PluginManager):
    plugin_manager.load_setuptools_entrypoints("cfripper")  # Dynamically load plugins using entry points
    plugin_manager.register(rules)  # Register default rules


def get_all_rules():
    plugin_manager = setup_plugin_manager()
    load_all_plugins(plugin_manager)
    plugins_output = plugin_manager.hook.cfripper_get_rules()
    rules = {k: v for d in plugins_output for k, v in d.items()}
    return rules
