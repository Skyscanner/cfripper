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


class Result(object):
    """An object to represent scan results."""

    def __init__(self):
        self.valid = True
        self.failed_rules = []
        self.exceptions = []
        self.failed_monitored_rules = []
        self.warnings = []

    def add_failure(self, rule, reason, monitor_mode):
        if monitor_mode:
            self.add_failed_monitored_rule(rule, reason)
            return

        if self.valid:
            self.valid = False
        self.failed_rules.append(
            {
                "rule": rule,
                "reason": reason,
            }
        )

    def add_exception(self, ex):
        self.exceptions.append(ex)

    def add_warning(self, warning):
        self.warnings.append(warning)

    def add_failed_monitored_rule(self, rule, reason):
        self.failed_monitored_rules.append(
            {
                "rule": rule,
                "reason": reason,
            }
        )
