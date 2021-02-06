from typing import Dict, Optional

from pluggy.manager import importlib_metadata
from pycfmodel.model.cf_model import CFModel

from cfripper import rules
from cfripper.config.pluggy import hookimpl
from cfripper.config.pluggy.utils import get_all_rules, load_all_plugins, setup_plugin_manager
from cfripper.model.result import Result
from cfripper.rules import DEFAULT_RULES
from cfripper.rules.base_rules import Rule


def test_default_rules_are_imported():
    plugin_manager = setup_plugin_manager()
    load_all_plugins(plugin_manager)
    plugins = plugin_manager.list_name_plugin()
    assert len(plugins) == 1
    plugin_name, plugin_module = next(iter(plugins))
    assert plugin_name == "cfripper.rules"
    assert plugin_module == rules


def test_load_setuptools_instantiation(monkeypatch):
    # Test adapted from https://github.com/pytest-dev/pluggy/blob/0a064fe275060dbdb1fe6e10c888e72bc400fb33/testing/test_pluginmanager.py#L423

    class EntryPoint:
        name = "cfripper_plugin"
        group = "cfripper"
        value = "cfripper_plugin:foo"

        def load(self):
            class PseudoPlugin:
                x = 42

            return PseudoPlugin()

    class Distribution:
        entry_points = (EntryPoint(),)

    dist = Distribution()

    def my_distributions():
        return (dist,)

    monkeypatch.setattr(importlib_metadata, "distributions", my_distributions)

    plugin_manager = setup_plugin_manager()

    num_loaded_plugins = plugin_manager.load_setuptools_entrypoints("cfripper")
    assert num_loaded_plugins == 1

    plugin = plugin_manager.get_plugin("cfripper_plugin")
    assert plugin.x == 42

    plugins_distinfo = plugin_manager.list_plugin_distinfo()
    assert len(plugins_distinfo) == 1
    plugin_name, plugin_module = next(iter(plugins_distinfo))
    assert plugin_name == plugin
    assert plugin_module._dist == dist

    num_loaded_plugins = plugin_manager.load_setuptools_entrypoints("cfripper")
    assert num_loaded_plugins == 0  # no plugin loaded by this call


def test_get_all_rules_returns_default_rules():
    rules = get_all_rules()
    assert rules == DEFAULT_RULES


def test_get_all_rules_returns_default_rules_and_plugin_rules(monkeypatch):
    class DummyRule(Rule):
        def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
            pass

    class EntryPoint:
        name = "cfripper_plugin"
        group = "cfripper"
        value = "cfripper_plugin:foo"

        def load(self):
            class PseudoPlugin:
                @hookimpl
                def cfripper_get_rules(self):
                    return {DummyRule.__name__: DummyRule}

            return PseudoPlugin()

    class Distribution:
        entry_points = (EntryPoint(),)

    dist = Distribution()

    def my_distributions():
        return (dist,)

    monkeypatch.setattr(importlib_metadata, "distributions", my_distributions)

    rules = get_all_rules()
    assert rules == {DummyRule.__name__: DummyRule, **DEFAULT_RULES}
