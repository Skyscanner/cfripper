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
from typing import Dict

from cfripper.model.enums import RuleMode


class Result:
    """An object to represent scan results."""

    def __init__(self):
        self.valid = True
        self.failed_rules = []
        self.exceptions = []
        self.failed_monitored_rules = []
        self.warnings = []

    def add_failure(
        self,
        rule: str,
        reason: str,
        rule_mode: str,
        risk_value: str,
        granularity: str,
        resource_ids=None,
        actions=None,
    ):

        if resource_ids is None:
            resource_ids = set()

        if actions is None:
            actions = set()

        failure = {
            "rule": rule,
            "reason": reason,
            "rule_mode": rule_mode,
            "risk_value": risk_value,
            "resource_ids": resource_ids,
            "actions": actions,
            "granularity": granularity,
        }

        if rule_mode is not RuleMode.BLOCKING:
            self.add_failure_monitored_rule(failure=failure)
            return

        if self.valid:
            self.valid = False

        self.add_failure_blocking_rule(failure=failure)

    def add_exception(self, ex):
        self.exceptions.append(ex)

    def add_warning(self, warning):
        self.warnings.append(warning)

    def add_failure_monitored_rule(self, failure: Dict):
        self.failed_monitored_rules.append(failure)

    def add_failure_blocking_rule(self, failure: Dict):
        self.failed_rules.append(failure)
