import argparse
import logging
import os

import pycfmodel

from .config.config import Config
from .config.logger import setup_logging
from .main import perform_logging
from .model.result import Result
from .model.rule_processor import RuleProcessor
from .model.utils import convert_json_or_yaml_to_dict
from .rules import DEFAULT_RULES


def run():
    parser = argparse.ArgumentParser()
    parser.add_argument("--template", help="The cloudformation template in JSON or YAML format")
    arguments = parser.parse_args()

    templateInput = arguments.template

    logger = logging.getLogger(__file__)
    setup_logging()
    result = Result()

    templateDict = convert_json_or_yaml_to_dict(templateInput)
    if not templateDict:
        # In case of an invalid template
        result.add_exception(TypeError(f"Malformed Template - could not parse!! Template: {str(templateInput)}"))
        logger.exception(f"Malformed Template - could not parse!! Template: {str(templateInput)}")
        exit(1)

    repo_name = os.environ["REPO_NAME"]
    service_name = os.environ["SERVICE_NAME"]
    service_type = os.environ["SERVICE_TYPE"]
    region = os.environ["AWS_REGION"]

    #  Process Rules
    config = Config(
        project_name=repo_name,
        service_name=service_name,
        stack_name=f"{service_type}-{service_name}-service",
        rules=DEFAULT_RULES.keys(),
        aws_region=region,
    )
    logger.info("Scan started for: {}; {}; {};".format(config.project_name, config.service_name, config.stack_name))

    rules = [DEFAULT_RULES.get(rule)(config, result) for rule in config.rules]
    processor = RuleProcessor(*rules)

    cfmodel = pycfmodel.parse(templateDict).resolve()
    processor.process_cf_template(cfmodel, config, result)
    perform_logging(result, config)

    reasons_info = ",\n".join(["{}-{}".format(r.rule, r.reason) for r in result.failed_rules])
    failed_rules_info = [
        f"{failure.serializable()}\n" for failure in RuleProcessor.remove_debug_rules(rules=result.failed_rules)
    ]
    exceptions_info = [f"{x.args[0]}\n" for x in result.exceptions]
    warnings_info = [
        f"{failure.serializable()}\n"
        for failure in RuleProcessor.remove_debug_rules(rules=result.failed_monitored_rules)
    ]
    logger.info(
        (
            f"\nTemplate Scan Results:\n"
            f"Valid: {result.valid}\n"
            f"Reasons: {reasons_info}\n"
            f"Failed Rules: {failed_rules_info}\n"
            f"Exceptions: {exceptions_info}\n"
            f"Warnings: {warnings_info}"
        )
    )
    if(not result.valid):
        exit(1)
    else:
        exit(0)
