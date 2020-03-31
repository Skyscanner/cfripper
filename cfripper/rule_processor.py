import logging
import re
from typing import Dict, List, Optional

from pycfmodel.model.cf_model import CFModel

from cfripper.config.config import Config
from cfripper.model.enums import RuleGranularity, RuleMode
from cfripper.model.result import Failure, Result

logger = logging.getLogger(__file__)


class RuleProcessor:
    def __init__(self, *args):
        self.rules = args

    def process_cf_template(self, cfmodel: CFModel, config: Config, extras: Optional[Dict] = None) -> Result:
        result = Result()
        for rule in self.rules:
            try:
                result += rule.invoke(cfmodel, extras)
            except Exception as other_exception:
                result.add_exception(other_exception)
                logger.exception(
                    "{} crashed with {} for project - {}, service - {}, stack - {}".format(
                        type(rule).__name__,
                        type(other_exception).__name__,
                        config.project_name,
                        config.service_name,
                        config.stack_name,
                    )
                )
                continue
        self.remove_failures_of_whitelisted_actions(config=config, result=result)
        self.remove_failures_of_whitelisted_resources(config=config, result=result)
        return result

    @staticmethod
    def remove_debug_rules(rules: List[Failure]):
        return [rule for rule in rules if rule.rule_mode != RuleMode.DEBUG]

    @staticmethod
    def remove_failures_of_whitelisted_resources(config: Config, result: Result):

        if not result.failed_rules:
            return

        clean_failures = []

        for failure in result.failed_rules:
            if failure.granularity != RuleGranularity.RESOURCE:
                clean_failures.append(failure)
                continue

            if not failure.resource_ids:
                logger.warning(f"Failure with resource granularity doesn't have resources: {failure}")
                continue

            whitelisted_resources = {
                resource
                for resource in failure.resource_ids
                if any(
                    [
                        re.match(whitelisted_resource_regex, resource)
                        for whitelisted_resource_regex in config.get_whitelisted_resources(failure.rule)
                    ]
                )
            }
            failure.resource_ids = failure.resource_ids - whitelisted_resources
            if failure.resource_ids:
                clean_failures.append(failure)

        result.failed_rules = clean_failures

    @staticmethod
    def remove_failures_of_whitelisted_actions(config: Config, result: Result):

        if not result.failed_rules:
            return

        clean_failures = []

        for failure in result.failed_rules:
            if failure.granularity != RuleGranularity.ACTION:
                clean_failures.append(failure)
                continue

            if not failure.actions:
                logger.warning(f"Failure with action granularity doesn't have actions: {failure}")
                continue

            whitelisted_actions = {
                action
                for action in failure.actions
                if any(
                    [
                        re.match(whitelisted_action_regex, action)
                        for whitelisted_action_regex in config.get_whitelisted_actions(failure.rule)
                    ]
                )
            }
            failure.actions = failure.actions - whitelisted_actions
            if failure.actions:
                clean_failures.append(failure)

        result.failed_rules = clean_failures
