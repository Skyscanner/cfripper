import inspect
from cfripper import rules


def define_env(env):
    """
    This is the hook for defining variables, macros and filters

    - variables: the dictionary that contains the environment variables
    - macro: a decorator function, to declare a macro.
    """

    env.variables['baz'] = "John Doe"

    @env.macro
    def cfripper_rules():
        rules_inspection = inspect.getmembers(rules, inspect.isclass)
        results = []
        for _, klass in rules_inspection:
            doc = inspect.getdoc(klass)
            if not doc.startswith('Helper class that'):
                results.append((klass.__name__, doc))
            else:
                results.append((klass.__name__, None))
        return sorted(results)
