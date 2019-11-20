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
import logging
from typing import List, Set

from cfripper.model.enums import RuleMode
from cfripper.model.rule import Rule
from cfripper.model.utils import get_account_id_from_principal

logger = logging.getLogger(__file__)


class PrincipalCheckingRule(Rule):
    _valid_principals = None

    def _get_whitelist_from_config(self, services: List[str] = None) -> Set[str]:
        if services is None:
            services = self._config.aws_service_accounts.keys()

        unique_list = set()
        for service in services:
            unique_list |= set(self._config.aws_service_accounts[service])
        return unique_list

    @property
    def valid_principals(self) -> Set[str]:
        if self._valid_principals is None:
            self._valid_principals = {
                *self._config.aws_principals,
                *self._get_whitelist_from_config(),
            }
            if self._config.aws_account_id:
                self._valid_principals.add(self._config.aws_account_id)
        return self._valid_principals


class CrossAccountCheckingRule(PrincipalCheckingRule):
    @property
    def valid_principals(self) -> Set[str]:
        if self._valid_principals is None:
            self._valid_principals = self._get_whitelist_from_config()
            if self._config.aws_account_id:
                self._valid_principals.add(self._config.aws_account_id)
        return self._valid_principals

    def _do_statement_check(self, logical_id, statement):

        if statement.Effect == "Allow":
            for principal in statement.get_principal_list():
                account_id = get_account_id_from_principal(principal)
                if account_id not in self.valid_principals:
                    if statement.Condition and statement.Condition.dict():
                        logger.warning(
                            f"Not adding {type(self).__name__} failure in {logical_id} "
                            f"because there are conditions: {statement.Condition}"
                        )
                    elif not self._config.aws_account_id:
                        logger.warning(
                            f"Not adding {type(self).__name__} failure in {logical_id} "
                            f"because no AWS Account ID was found in the config."
                        )
                    elif "GETATT" in principal or "UNDEFINED_" in principal:
                        self.add_failure(
                            type(self).__name__,
                            self.REASON.format(logical_id, principal),
                            rule_mode=RuleMode.DEBUG,
                            resource_ids={logical_id},
                        )
                    else:
                        self.add_failure(
                            type(self).__name__, self.REASON.format(logical_id, principal), resource_ids={logical_id}
                        )
