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

from cfripper.config.regex import REGEX_FULL_WILDCARD_PRINCIPAL
from cfripper.model.rule_processor import Rule
from cfripper.rules.WildcardPrincipal import GenericWildcardPrincipal


class FullWildcardPrincipal(GenericWildcardPrincipal):

    REASON_WILCARD_PRINCIPAL = "{} should not allow wildcards in principals (principal: '{}')"

    RULE_MODE = Rule.BLOCKING
    RISK_VALUE = Rule.HIGH

    FULL_REGEX = REGEX_FULL_WILDCARD_PRINCIPAL
