from pluggy import PluginManager

from cfripper import hookspecs, rules


def get_plugin_manager():
    pm = PluginManager("cfripper")
    pm.add_hookspecs(hookspecs)
    pm.load_setuptools_entrypoints("cfripper")
    pm.register(rules)
    return pm


def get_all_rules():
    pm = get_plugin_manager()
    plugins_output = pm.hook.cfripper_get_rules()
    rules = {k: v for d in plugins_output for k, v in d.items()}
    return rules
