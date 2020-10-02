import importlib
import inspect
import re
from collections import OrderedDict
from textwrap import dedent
from typing import List

import click

from cfripper import rules
from cfripper.cli import cli
from cfripper.model.enums import RuleMode, RuleRisk


def define_env(env):
    @env.macro
    def cfripper_rules():
        severity_map = {RuleRisk.HIGH: "**High**", RuleRisk.MEDIUM: "Medium", RuleRisk.LOW: "Low"}
        rules_inspection = inspect.getmembers(rules, inspect.isclass)
        results = []
        for _, klass in rules_inspection:
            doc = inspect.getdoc(klass)
            parsed_doc = parse_doc_string(doc)

            content = ""
            for paragraph_title, paragraph_text in parsed_doc.items():
                if paragraph_title == "Description":
                    # Remove ABCMeta default docstring
                    if not paragraph_text.startswith("Helper class that"):
                        content += paragraph_text
                    content += f"\n\n>Severity: {severity_map[klass.RISK_VALUE]}\n"
                    if klass.RULE_MODE == RuleMode.MONITOR:
                        content += "\n>Defaults to monitor mode (rule not enforced)\n"
                    if klass.RULE_MODE == RuleMode.DEBUG:
                        content += "\n>Defaults to debug mode (rule not enforced)\n"
                else:
                    content += f"\n#### {paragraph_title}\n"
                    content += f"{paragraph_text}\n"

            results.append((klass.__name__, content))

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


def regex_for_splitting_paragraphs(sections: List[str]) -> re.Pattern:
    return re.compile(r"\s*(" + "|".join(sections) + r"):")


def process_paragraph(paragraph: str) -> str:
    return dedent(paragraph)


def parse_doc_string(doc):
    sections = ["Risk", "Fix", "Code for fix", "Filters context"]
    result = OrderedDict()
    pattern_for_paragraphs = regex_for_splitting_paragraphs(sections)
    paragraphs = pattern_for_paragraphs.split(doc.strip())
    # Grab class summary
    if paragraphs[0] not in sections:
        result["Description"] = process_paragraph(paragraphs.pop(0))
    # Add sections
    for paragraph_title, paragraph_text in zip(paragraphs[0::2], paragraphs[1::2]):
        result[paragraph_title] = process_paragraph(paragraph_text)
    return result
