"""
Copyright 2018 Skyscanner Ltd

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

from cfripper.config.config import Config
from cfripper.s3_adapter import S3Adapter
from cfripper.model.rule_processor import RuleProcessor
from cfripper.rules import ALL_RULES
from cfripper.model.result import Result
from cfripper.config.logger import get_logger

logger = get_logger()


def log_results(project_name, service_name, stack_name, rules, _type, warnings, template_url):
    logger.info("{}: project - {}, service- {}, stack - {}. {} {} URL: {}".format(
        _type,
        project_name,
        service_name,
        stack_name,
        json.dumps(rules),
        str(warnings),
        template_url,
    ))


def handler(event, context):
    """
    Main entry point of the Lambda function.

    :param event: {
        "stack_template_url": String
    }
    :param context:
    :return:
    """
    if not event.get("stack_template_url"):
        raise ValueError("Invalid event type: no parameter 'stack_template_url' in request.")

    result = Result()

    s3 = S3Adapter()
    template = s3.download_template_to_dictionary(event["stack_template_url"])
    if not template:
        # In case of an ivalid script log a warning and return early
        result.add_exception(TypeError("Malformated CF script: {}".format(event["stack_template_url"])))
        return {
            "valid": "true",
            "reason": '',
            "failed_rules": [],
            "exceptions": [x.args[0] for x in result.exceptions],
        }

    # Process Rules
    config = Config(
        project_name=event.get("project"),
        service_name=event.get("serviceName"),
        stack_name=event.get("stack", {}).get("name"),
        rules=ALL_RULES.keys(),
    )

    logger.info("Scan started for: {}; {}; {};".format(
        config.project_name,
        config.service_name,
        config.stack_name,
    ))

    rules = [ALL_RULES.get(rule)(config, result) for rule in config.RULES]
    processor = RuleProcessor(*rules)

    processor.process_cf_template(template, config, result)

    if not result.valid:
        log_results(
            "Failed rules",
            config.project_name,
            config.service_name,
            config.stack_name,
            result.failed_rules,
            result.warnings,
            event["stack_template_url"],
        )
        logger.info("FAIL: {}; {}; {}".format(
            config.project_name,
            config.service_name,
            config.stack_name,
        ))
    else:
        logger.info("PASS: {}; {}; {}".format(
            config.project_name,
            config.service_name,
            config.stack_name,
        ))
    if len(result.failed_monitored_rules) > 0 or len(result.warnings) > 0:
        log_results(
            "Failed monitored rules",
            config.project_name,
            config.service_name,
            config.stack_name,
            result.failed_monitored_rules,
            result.warnings,
            event["stack_template_url"],
        )
    return {
        "valid": str(result.valid).lower(),
        "reason": ",".join(["{}-{}".format(r["rule"], r["reason"]) for r in result.failed_rules]),
        "failed_rules": result.failed_rules,
        "exceptions": [x.args[0] for x in result.exceptions],
        "warnings": result.failed_monitored_rules,
    }
