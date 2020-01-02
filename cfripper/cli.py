import json
import logging
import sys
from io import TextIOWrapper
from pathlib import Path
from typing import Dict, Optional

import click
import pycfmodel
from pycfmodel.model.cf_model import CFModel

from cfripper.__version__ import __version__
from cfripper.config.config import Config
from cfripper.model.result import Result
from cfripper.model.utils import convert_json_or_yaml_to_dict
from cfripper.rule_processor import RuleProcessor
from cfripper.rules import DEFAULT_RULES


def setup_logging(level: str) -> None:
    logging.basicConfig(level=logging._nameToLevel[level], format="%(message)s")


def get_cfmodel(file: TextIOWrapper) -> CFModel:
    template = convert_json_or_yaml_to_dict(file.read())
    cfmodel = pycfmodel.parse(template)
    return cfmodel


def format_result(result: Result, format: str) -> str:
    if format == "json":
        return json.dumps(
            {
                "valid": result.valid,
                "reason": ",".join(["{}-{}".format(r.rule, r.reason) for r in result.failed_rules]),
                "failed_rules": [
                    failure.serializable() for failure in RuleProcessor.remove_debug_rules(rules=result.failed_rules)
                ],
                "exceptions": [x.args[0] for x in result.exceptions],
                "warnings": [
                    failure.serializable()
                    for failure in RuleProcessor.remove_debug_rules(rules=result.failed_monitored_rules)
                ],
            },
            indent=2,
            sort_keys=True,
        )
    text = f"Valid: {result.valid}"
    for failed_rule in result.failed_rules:
        text += f"{failed_rule.rule}: {failed_rule.reason}\n"
    return text


def process_file(
    file, resolve: bool, resolve_parameters: Optional[Dict], output_folder: Optional[str], format: str
) -> None:
    logging.info(f"Analysing {file.name}...")
    cfmodel = get_cfmodel(file)
    if resolve:
        cfmodel = cfmodel.resolve(resolve_parameters)
    config = Config(rules=DEFAULT_RULES.keys())
    result = Result()
    rules = [DEFAULT_RULES.get(rule)(config, result) for rule in config.rules]
    rule_processor = RuleProcessor(*rules)

    rule_processor.process_cf_template(cfmodel, config, result)

    formatted_result = format_result(result, format)
    if output_folder:
        save_output(Path(output_folder), f"{file.name}.cfripper.results.{format}", formatted_result)
    else:
        click.echo(formatted_result)


def save_output(folder: Path, filename: str, data: str) -> None:
    with open(folder / filename, "w") as output_file:
        output_file.write(data)
    logging.info(f"Result saved in {folder / filename}")


@click.command()
@click.version_option(prog_name="cfripper", version=__version__)
@click.argument("files", type=click.File("r"), nargs=-1)
@click.option(
    "--resolve/--no-resolve",
    is_flag=True,
    default=False,
    help="Resolves cloudformation intrinsic functions",
    show_default=True,
)
@click.option(
    "--resolve-parameters", type=click.File("r"), help="JSON file specifying parameters to use for resolve",
)
@click.option(
    "--format",
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
    type=click.Choice(logging._nameToLevel.keys(), case_sensitive=True),
    default="INFO",
    help="Logging level",
    show_default=True,
)
def cli(files, logging_level, resolve_parameters, **kwargs):
    """Analyse AWS Cloudformation templates passed by parameter."""
    try:
        setup_logging(logging_level)

        if kwargs["resolve"] and resolve_parameters:
            resolve_parameters = convert_json_or_yaml_to_dict(resolve_parameters.read())

        for file in files:
            process_file(file=file, resolve_parameters=resolve_parameters, **kwargs)

    except Exception as e:
        logging.error(str(e))
        logging.debug("", exc_info=True)
        try:
            sys.exit(e.errno)
        except AttributeError:
            sys.exit(1)


if __name__ == "__main__":
    cli()
