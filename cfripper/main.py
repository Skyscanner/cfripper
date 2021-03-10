import json
import logging
from typing import Any, Dict, Optional

import pycfmodel

from cfripper.rule_processor import RuleProcessor

from .boto3_client import Boto3Client
from .config.config import Config
from .config.logger import setup_logging
from .model.enums import RuleMode
from .model.result import Result
from .rules import DEFAULT_RULES

logger = logging.getLogger(__file__)
DEFAULT_EXTRA_KEYS_FROM_EVENT = ("account", "event", "project", "region", "stack", "tags")


def log_results(project_name, service_name, stack_name, rules, _type, template_url):
    logger.info(
        "{}: project - {}, service- {}, stack - {}. {} URL: {}".format(
            _type, project_name, service_name, stack_name, json.dumps(rules), template_url
        )
    )


def perform_logging(result, config, event):
    if not result.valid:
        log_results(
            "Failed rules",
            config.project_name,
            config.service_name,
            config.stack_name,
            result.failures,
            event.get("stack_template_url", "N/A"),
        )
        logger.info("FAIL: {}; {}; {}".format(config.project_name, config.service_name, config.stack_name))
    else:
        logger.info("PASS: {}; {}; {}".format(config.project_name, config.service_name, config.stack_name))


def handler(event, context):
    """
    Main entry point of the Lambda function.

    :param event: {
        "stack_template_url": String,
        "project": String,
        "stack": {
            "name": String,
        },
        "event": String,
        "region": String,
        "account": {
            "name": String,
            "id": String,
        },
        "user_agent": String,
    }
    :param context:
    :return:
    """

    setup_logging()
    if not event.get("stack_template_url") and not event.get("stack", {}).get("name"):
        raise ValueError("Invalid event type: no parameter 'stack_template_url' or 'stack::name' in request.")

    boto3_client = get_boto3_client(event)
    template = get_template(boto3_client, event)
    aws_exports = get_exports(boto3_client)
    extras = get_extras(event)

    if not template:
        # In case of an invalid script log a warning and return early
        result = Result()
        result.add_exception(TypeError(f"Malformed Event - could not parse!! Event: {str(event)}"))
        logger.exception(f"Malformed Event - could not parse!! Event: {str(event)}")
        return {"valid": True, "reason": "", "failed_rules": [], "exceptions": [x.args[0] for x in result.exceptions]}

    # Process Rules
    config = Config(
        project_name=event.get("project"),
        service_name=event.get("serviceName"),
        stack_name=event.get("stack", {}).get("name"),
        rules=DEFAULT_RULES.keys(),
        event=event.get("event"),
        template_url=event.get("stack_template_url", "N/A"),
        aws_region=event.get("region", "N/A"),
        aws_account_name=event.get("account", {}).get("name", "N/A"),
        aws_account_id=event.get("account", {}).get("id", "N/A"),
        aws_user_agent=event.get("user_agent", "N/A"),
    )

    logger.info("Scan started for: {}; {}; {};".format(config.project_name, config.service_name, config.stack_name))

    rules = [DEFAULT_RULES.get(rule)(config) for rule in config.rules]
    processor = RuleProcessor(*rules)

    cfmodel = pycfmodel.parse(template).resolve(extra_params=aws_exports)

    result = processor.process_cf_template(cfmodel=cfmodel, config=config, extras=extras)

    perform_logging(result, config, event)

    return {
        "valid": result.valid,
        "reason": ",".join(
            [f"{failure.rule}-{failure.reason}" for failure in result.get_failures(exclude_rule_modes={RuleMode.DEBUG})]
        ),
        "failed_rules": [
            failure.serializable() for failure in result.get_failures(exclude_rule_modes={RuleMode.DEBUG})
        ],
        "exceptions": [x.args[0] for x in result.exceptions],
    }


def get_extras(event) -> Dict[str, Any]:
    return {k: v for k, v in event.items() if k in DEFAULT_EXTRA_KEYS_FROM_EVENT}


def get_boto3_client(event) -> Optional[Boto3Client]:
    try:
        account_id = event.get("account", {}).get("id")
        region = event.get("region")
        stack_name = event.get("stack", {}).get("name")
        boto3_client = Boto3Client(account_id, region, stack_name)
    except Exception:
        boto3_client = None
        logger.exception("Could not create Boto3 Cloudformation Client...")
    return boto3_client


def get_template(boto3_client: Boto3Client, event) -> Optional[Dict]:
    template = None
    if boto3_client:
        account_id = event.get("account", {}).get("id")
        region = event.get("region")
        stack_name = event.get("stack", {}).get("name")
        try:
            if event.get("stack_template_url"):
                template = boto3_client.download_template_to_dictionary(event["stack_template_url"])
            else:
                logger.info("stack_template_url not available")
        except Exception:
            logger.exception(
                f"Error calling download_template_to_dictionary for: {stack_name} on {account_id} - {region}"
            )

        if not template:
            try:
                template = boto3_client.get_template()
            except Exception:
                logger.exception(f"Error calling get_template for: {stack_name} on {account_id} - {region}")
    return template


def get_exports(boto3_client: Boto3Client) -> Dict[str, str]:
    return boto3_client.get_exports() if boto3_client else {}
