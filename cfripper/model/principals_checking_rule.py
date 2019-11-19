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
from cfripper.model.rule import Rule


class PrincipalCheckingRule(Rule):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._valid_principals = None

    @property
    def valid_principals(self):
        if self._valid_principals is None:
            self._valid_principals = {
                *self._config.aws_service_accounts,
                *self._config.aws_principals,
                self._config.aws_account_id,
            }
        return self._valid_principals