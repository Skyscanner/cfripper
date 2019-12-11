import inspect

from cfripper import rules


def define_env(env):
    @env.macro
    def cfripper_rules():
        rules_inspection = inspect.getmembers(rules, inspect.isclass)
        results = []
        for _, klass in rules_inspection:
            doc = inspect.getdoc(klass)
            # Remove ABCMeta default docstring
            if not doc.startswith("Helper class that"):
                results.append((klass.__name__, doc))
            else:
                results.append((klass.__name__, None))
        return sorted(results)
