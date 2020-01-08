import importlib
import inspect

import click

from cfripper import rules
from cfripper.cli import cli
from cfripper.model.enums import RuleMode, RuleRisk


def define_env(env):
    @env.macro
    def cfripper_rules():
        rules_inspection = inspect.getmembers(rules, inspect.isclass)
        results = []
        for _, klass in rules_inspection:
            doc = inspect.getdoc(klass)

            summary, risk, fix_text, fix_code = parse_doc_string(doc)

            # Remove ABCMeta default docstring
            if summary.startswith("Helper class that"):
                summary = ""
            if klass.RULE_MODE == RuleMode.MONITOR:
                summary += "\nDefaults to monitor mode (rule not enforced)\n"
            if klass.RULE_MODE == RuleMode.DEBUG:
                summary += "\nDefaults to debug mode (rule not enforced)\n"

            severity_map = {RuleRisk.HIGH: "High", RuleRisk.MEDIUM: "Medium", RuleRisk.LOW: "Low"}

            results.append(
                (
                    klass.__name__,
                    summary.replace("\n", "\n\n"),
                    severity_map.get(klass.RISK_VALUE),
                    risk,
                    fix_text,
                    fix_code,
                )
            )

        return sorted(results)

    @env.macro
    def inline_source(reference):
        obj = get_object_from_reference(reference)
        source = "".join(inspect.getsourcelines(obj)[0])
        return f"```python3\n{source}```"

    @env.macro
    def cfripper_cli_help():
        with click.Context(cli) as ctx:
            return cli.get_help(ctx)


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


def parse_doc_string(doc):
    lines = doc.split("\n")

    summary, risk, fix_text, fix_code = "", "", "", ""
    summary_complete, risk_complete, fix_complete = False, False, False

    for line in lines:
        if line.startswith("Risk:"):
            summary_complete = True
            continue

        if line.startswith("Fix:"):
            risk_complete = True
            continue

        if line.startswith("Code for fix:"):
            fix_complete = True
            continue

        if not summary_complete:
            summary += line.strip()
            summary += "\n"
            continue

        if not risk_complete:
            risk += line.strip()
            risk += "\n"
            continue

        if not fix_complete:
            fix_text += line.strip()
            fix_text += "\n"
            continue

        fix_code += line
        fix_code += "\n"

    return summary, risk, fix_text, fix_code
