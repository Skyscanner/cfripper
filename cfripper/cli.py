import logging
import re
import sys
from io import TextIOWrapper
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import click
import pycfmodel
from pycfmodel.model.cf_model import CFModel

from cfripper.__version__ import __version__
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


def format_result(result: Result, output_format: str) -> str:
    if output_format == "json":
        return format_result_json(result)
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

    formatted_result = format_result(result, output_format)

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
@click.version_option(prog_name="cfripper", version=__version__)
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
    type=click.Choice(["json", "txt"], case_sensitive=False),
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
    default="INFO",
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
