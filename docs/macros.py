import importlib
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

    @env.macro
    def inline_source(reference):
        obj = get_object_from_reference(reference)
        source = "".join(inspect.getsourcelines(obj)[0])
        return f"```python3\n{source}```"


def get_object_from_reference(reference):
    split = reference.split(".")
    right = []
    module = None
    while split:
        try:
            module = importlib.import_module(".".join(split))
            break
        except ModuleNotFoundError:
            right.append(split.pop())
    if module:
        for entry in reversed(right):
            module = getattr(module, entry)
    return module
