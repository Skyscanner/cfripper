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
from ..config.regex import REGEX_FULL_WILDCARD_PRINCIPAL
from ..model.enums import RuleMode, RuleRisk
from .GenericWildcardPrincipalRule import GenericWildcardPrincipalRule


class FullWildcardPrincipalRule(GenericWildcardPrincipalRule):

    REASON_WILCARD_PRINCIPAL = "{} should not allow wildcards in principals (principal: '{}')"

    RULE_MODE = RuleMode.BLOCKING
    RISK_VALUE = RuleRisk.HIGH

    FULL_REGEX = REGEX_FULL_WILDCARD_PRINCIPAL
