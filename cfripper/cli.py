import logging
import re
import sys
from importlib.metadata import version
from io import TextIOWrapper
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from xml.etree import ElementTree as ET

import click
import pycfmodel
from pycfmodel.model.cf_model import CFModel

from cfripper.config.config import Config
from cfripper.config.pluggy.utils import get_all_rules
from cfripper.exceptions import FileEmptyException
from cfripper.model.enums import RuleMode
from cfripper.model.result import Result
from cfripper.model.utils import convert_json_or_yaml_to_dict
from cfripper.rule_processor import RuleProcessor

LOGGING_LEVELS = {
    "ERROR": logging.ERROR,
    "WARNING": logging.WARNING,
    "INFO": logging.INFO,
    "DEBUG": logging.DEBUG,
}


def setup_logging(level: str) -> None:
    logging.basicConfig(level=LOGGING_LEVELS[level], format="%(message)s")


def init_cfripper(
    rules_config_file: Optional[TextIOWrapper],
    rules_filters_folder: Optional[str],
    aws_account_id: Optional[str],
    aws_principals: Optional[List[str]],
) -> Tuple[Config, RuleProcessor]:
    rules = get_all_rules()
    config = Config(rules=rules.keys(), aws_account_id=aws_account_id, aws_principals=aws_principals)
    if rules_config_file:
        config.load_rules_config_file(rules_config_file)
    if rules_filters_folder:
        config.add_filters_from_dir(rules_filters_folder)
    rule_processor = RuleProcessor(*[rules.get(rule)(config) for rule in config.rules])
    return config, rule_processor


def get_cfmodel(template: TextIOWrapper) -> CFModel:
    template_file = convert_json_or_yaml_to_dict(template.read())
    if not template_file:
        raise FileEmptyException(f"{template.name} is empty and not a valid template.")
    cfmodel = pycfmodel.parse(template_file)
    return cfmodel


def analyse_template(cfmodel: CFModel, rule_processor: RuleProcessor, config: Config) -> Result:
    return rule_processor.process_cf_template(cfmodel, config)


def format_result_json(result: Result) -> str:
    return result.json()


def format_result_txt(result: Result) -> str:
    result_lines = [f"Valid: {result.valid}"]

    blocking_rules = result.get_failures(include_rule_modes={RuleMode.BLOCKING})
    if blocking_rules:
        result_lines.append("Issues found:")
        [result_lines.append(f"\t- {r.rule}: {r.reason}") for r in blocking_rules]

    monitoring_rules = result.get_failures(include_rule_modes={RuleMode.MONITOR})
    if monitoring_rules:
        result_lines.append("Monitored issues found:")
        [result_lines.append(f"\t- {r.rule}: {r.reason}") for r in monitoring_rules]

    return "\n".join(result_lines)


# Rule reasons embed resource ids, actions and, for some rules, fragments of the
# template itself, so they routinely contain `<`, `&` and other XML metacharacters.
# ElementTree escapes text and attribute values on serialisation, which is why the
# tree is built with `ET.SubElement` rather than by string formatting: hand-rolled
# XML would produce either invalid output or an injection point in a report that
# CI tooling parses.
_JUNIT_TESTSUITE_NAME = "cfripper"


def _build_junit_failure_message(failure) -> str:  # noqa: ANN001
    """Render one failure as the `<failure>` element's message, one fact per line."""
    lines = [failure.reason, f"rule: {failure.rule}", f"rule_mode: {failure.rule_mode.value}"]
    if failure.risk_value:
        lines.append(f"risk_value: {failure.risk_value.value}")
    if failure.resource_ids:
        lines.append(f"resource_ids: {', '.join(sorted(str(r) for r in failure.resource_ids))}")
    if failure.resource_types:
        lines.append(f"resource_types: {', '.join(sorted(str(r) for r in failure.resource_types))}")
    if failure.actions:
        lines.append(f"actions: {', '.join(sorted(str(a) for a in failure.actions))}")
    return "\n".join(lines)


def format_result_junit(result: Result, template_name: str = _JUNIT_TESTSUITE_NAME) -> str:
    """Render the result as a JUnit XML document.

    The mapping is one test case per *rule that was checked*, which is what a CI
    reporter expects: a failing case is a violation, and the pass/fail counts add
    up to the rules that ran. Only rules that produced a failure are reported
    individually — the result does not carry the list of rules that passed, so
    the suite's counts are derived from the failures it does have rather than
    invented. `errors` counts the exceptions the scan raised, which is why they
    are emitted as `<error>` elements: they are the scan failing to complete, not
    a template violating a rule.
    """
    suite = ET.Element("testsuite", {"name": template_name})

    # `exceptions` and `failures` are the only signals the Result carries, so the
    # counts are their lengths. A template that passes every rule yields a suite
    # with zero cases, which JUnit readers accept as "nothing to report".
    suite.set("tests", str(len(result.failures) + len(result.exceptions)))
    suite.set("failures", str(len(result.failures)))
    suite.set("errors", str(len(result.exceptions)))
    suite.set("skipped", "0")

    for exception in result.exceptions:
        case = ET.SubElement(suite, "testcase", {"name": f"exception: {type(exception).__name__}"})
        error = ET.SubElement(case, "error", {"message": str(exception)})
        error.set("type", type(exception).__name__)

    for failure in result.failures:
        case = ET.SubElement(suite, "testcase", {"name": failure.rule})
        node = ET.SubElement(case, "failure", {"message": failure.reason})
        node.set("type", failure.risk_value.value if failure.risk_value else failure.rule_mode.value)
        # The element's text carries the full detail; `message` is kept short
        # because CI UIs render it inline and truncate.
        node.text = _build_junit_failure_message(failure)

    return ET.tostring(suite, encoding="unicode")


def format_result(result: Result, output_format: str, template_name: str = _JUNIT_TESTSUITE_NAME) -> str:
    if output_format == "json":
        return format_result_json(result)
    elif output_format == "junit":
        return format_result_junit(result, template_name=template_name)
    else:
        return format_result_txt(result)


def save_to_file(path: Path, result: str) -> None:
    path.write_text(result)
    logging.info(f"Result saved in {path}")


def print_to_stdout(result: str) -> None:
    click.echo(result)


def output_handling(template_name: str, result: str, output_format: str, output_folder: Optional[str]) -> None:
    if output_folder:
        save_to_file(Path(output_folder) / f"{template_name}.cfripper.results.{output_format}", result)
    else:
        print_to_stdout(result)


def process_template(
    template: TextIOWrapper,
    resolve: bool,
    resolve_parameters: Optional[Dict],
    output_folder: Optional[str],
    output_format: str,
    rules_config_file: Optional[TextIOWrapper],
    rules_filters_folder: Optional[str],
    aws_account_id: Optional[str],
    aws_principals: Optional[List[str]],
) -> bool:
    logging.info(f"Analysing {template.name}...")

    cfmodel = get_cfmodel(template)
    if resolve:
        cfmodel = cfmodel.resolve(resolve_parameters)

    config, rule_processor = init_cfripper(rules_config_file, rules_filters_folder, aws_account_id, aws_principals)

    result = analyse_template(cfmodel, rule_processor, config)

    # The JUnit suite is named after the template so a multi-template run
    # produces distinguishable suites in one report.
    formatted_result = format_result(result, output_format, template_name=Path(template.name).name)

    output_handling(template.name, formatted_result, output_format, output_folder)

    return result.valid


def validate_aws_account_id(ctx: click.Context, param: str, value: str) -> Optional[str]:
    if value in [None, ""]:
        return None
    if re.match("^[0-9]{12}$", str(value)):
        return str(value)
    else:
        raise click.BadParameter("AWS Account ID needs to be 12 digits – are you missing 0 prefixes?")


def validate_aws_principals(ctx: click.Context, param: str, value: str) -> Optional[List[str]]:
    if value in [None, ""]:
        return None
    return str(value).split(",")


@click.command()
@click.version_option(prog_name="cfripper", version=version("cfripper"))
@click.argument("templates", type=click.File("r"), nargs=-1)
@click.option(
    "--resolve/--no-resolve",
    is_flag=True,
    default=False,
    help="Resolves cloudformation variables and intrinsic functions",
    show_default=True,
)
@click.option(
    "--resolve-parameters",
    type=click.File("r"),
    help=(
        "JSON/YML file containing key-value pairs used for resolving CloudFormation files with templated parameters. "
        'For example, {"abc": "ABC"} will change all occurrences of {"Ref": "abc"} in the CloudFormation file to "ABC".'
    ),
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "txt", "junit"], case_sensitive=False),
    default="txt",
    help="Output format",
    show_default=True,
)
@click.option(
    "--output-folder",
    type=click.Path(exists=True, resolve_path=True, writable=True, file_okay=False),
    help="If not present, result will be sent to stdout",
)
@click.option(
    "--logging",
    "logging_level",
    type=click.Choice(LOGGING_LEVELS.keys(), case_sensitive=True),
    default="WARNING",
    help="Logging level",
    show_default=True,
)
@click.option(
    "--rules-config-file",
    type=click.File("r"),
    help="Loads rules configuration file (type: [.py, .pyc])",
)
@click.option(
    "--rules-filters-folder",
    type=click.Path(exists=True, resolve_path=True, readable=True, file_okay=False),
    help="All files in the folder must be of type: [.py, .pyc]",
)
@click.option(
    "--aws-account-id",
    type=click.STRING,
    callback=validate_aws_account_id,
    help="A 12-digit AWS account number eg. 123456789012",
)
@click.option(
    "--aws-principals",
    type=click.STRING,
    callback=validate_aws_principals,
    help="A comma separated list of AWS principals eg. arn:aws:iam::123456789012:root,234567890123,"
    "arn:aws:iam::111222333444:user/user-name",
)
def cli(templates, logging_level, resolve_parameters, **kwargs):
    """
    Analyse AWS Cloudformation templates passed by parameter.
    Exit codes:
      - 0 = all templates valid and scanned successfully
      - 1 = error / issue in scanning at least one template
      - 2 = at least one template is not valid according to CFRipper (template scanned successfully)
      - 3 = unknown / unhandled exception in scanning the templates
    """
    try:
        setup_logging(logging_level)

        if kwargs["resolve"] and resolve_parameters:
            resolve_parameters = convert_json_or_yaml_to_dict(resolve_parameters.read())

        results_of_templates = [
            process_template(template=template, resolve_parameters=resolve_parameters, **kwargs)
            for template in templates
        ]
        sys.exit(2 if False in results_of_templates else 0)
    except FileEmptyException as file_empty:
        sys.exit(file_empty)
    except Exception as e:
        logging.exception(
            "Unhandled exception raised, please create an issue with the error message at "
            "https://github.com/Skyscanner/cfripper/issues"
        )
        try:
            sys.exit(e.errno)
        except AttributeError:
            sys.exit(3)


if __name__ == "__main__":
    cli()
