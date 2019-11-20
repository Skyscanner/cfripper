"""
Copyright 2018-2019 Skyscanner Ltd

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
"""
import json
import logging

import pycfmodel

from cfripper.rule_processor import RuleProcessor

from .boto3_client import Boto3Client
from .config.config import Config
from .config.logger import setup_logging
from .model.result import Result
from .rules import DEFAULT_RULES

logger = logging.getLogger(__file__)


def log_results(project_name, service_name, stack_name, rules, _type, warnings, template_url):
    logger.info(
        "{}: project - {}, service- {}, stack - {}. {} {} URL: {}".format(
            _type, project_name, service_name, stack_name, json.dumps(rules), str(warnings), template_url
        )
    )


def perform_logging(result, config, event):
    if not result.valid:
        log_results(
            "Failed rules",
            config.project_name,
            config.service_name,
            config.stack_name,
            result.failed_rules,
            result.warnings,
            event.get("stack_template_url", "N/A"),
        )
        logger.info("FAIL: {}; {}; {}".format(config.project_name, config.service_name, config.stack_name))
    else:
        logger.info("PASS: {}; {}; {}".format(config.project_name, config.service_name, config.stack_name))
    if len(result.failed_monitored_rules) > 0 or len(result.warnings) > 0:
        log_results(
            "Failed monitored rules",
            config.project_name,
            config.service_name,
            config.stack_name,
            result.failed_monitored_rules,
            result.warnings,
            event.get("stack_template_url", "N/A"),
        )


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

    result = Result()
    template = get_template(event)

    if not template:
        # In case of an invalid script log a warning and return early
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

    rules = [DEFAULT_RULES.get(rule)(config, result) for rule in config.rules]
    processor = RuleProcessor(*rules)

    # TODO get AWS variables/parameters and pass them to resolve
    cfmodel = pycfmodel.parse(template).resolve()

    processor.process_cf_template(cfmodel, config, result)

    perform_logging(result, config, event)

    return {
        "valid": result.valid,
        "reason": ",".join(["{}-{}".format(r.rule, r.reason) for r in result.failed_rules]),
        "failed_rules": [
            failure.serializable() for failure in RuleProcessor.remove_debug_rules(rules=result.failed_rules)
        ],
        "exceptions": [x.args[0] for x in result.exceptions],
        "warnings": [
            failure.serializable() for failure in RuleProcessor.remove_debug_rules(rules=result.failed_monitored_rules)
        ],
    }


def get_template(event):
    try:
        account_id = event.get("account", {}).get("id")
        region = event.get("region")
        stack_name = event.get("stack", {}).get("name")
        boto3_client = Boto3Client(account_id, region, stack_name)
    except Exception:
        boto3_client = None
        logger.exception("Could not create Boto3 Cloudformation Client...")
    template = None
    if boto3_client:
        try:
            if event.get("stack_template_url"):
                template = boto3_client.download_template_to_dictionary(event["stack_template_url"])
            else:
                logger.info(f"stack_template_url not available")
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
