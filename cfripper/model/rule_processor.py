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


import pycfmodel

from cfripper.config.logger import get_logger
from cfripper.config.config import Config
from cfripper.model.managed_policy_transformer import ManagedPolicyTransformer

logger = get_logger()


class Rule:
    MONITOR_MODE = False

    def __init__(self, config, result):
        self._config = config if config else Config()
        self._result = result

    def invoke(self, resources, parameters):
        raise NotImplementedError("Can't process the base Rule class.")

    def process_resource(self, logical_name, properties):
        raise NotImplementedError("Can't process the base Rule class.")

    def add_failure(self, rule, reason):
        self._result.add_failure(rule, reason, self.MONITOR_MODE)

    def add_warning(self, warning):
        self._result.add_warning(warning)


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
                logger.error("{} crashed with {} for project - {}, service- {}, stack - {}".format(
                    type(rule).__name__,
                    type(other_exception).__name__,
                    config.project_name,
                    config.service_name,
                    config.stack_name,
                ))
                result.add_exception(other_exception)
                logger.exception(other_exception)
                continue
