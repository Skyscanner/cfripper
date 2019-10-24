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
import logging
import re
from typing import List

import pycfmodel

from cfripper.config.config import Config
from cfripper.model.enums import RuleMode, RuleGranularity
from cfripper.model.managed_policy_transformer import ManagedPolicyTransformer
from cfripper.model.result import Result, Failure

logger = logging.getLogger(__file__)


class RuleProcessor:
    def __init__(self, *args):
        self.rules = args

    def process_cf_template(self, cf_template_dict, config, result):
        if not cf_template_dict or not isinstance(cf_template_dict, dict):
            result.add_exception(TypeError("CF template not converted to dict"))
            return

        cf_model = pycfmodel.parse(cf_template_dict)

        # Fetch referenced managed policies for validation
        transformer = ManagedPolicyTransformer(cf_model)
        transformer.transform_managed_policies()

        for rule in self.rules:
            try:
                rule.invoke(cf_model.resources, cf_model.parameters)
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
                if any([
                    re.match(whitelisted_resource_regex, resource)
                    for whitelisted_resource_regex in config.get_whitelisted_resources(failure.rule)
                ])
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
                if any([
                    re.match(whitelisted_action_regex, action)
                    for whitelisted_action_regex in config.get_whitelisted_actions(failure.rule)
                ])
            }
            failure.actions = failure.actions - whitelisted_actions
            if failure.actions:
                clean_failures.append(failure)

        result.failed_rules = clean_failures
