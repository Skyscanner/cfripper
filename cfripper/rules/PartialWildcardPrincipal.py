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
import re

from ..model.enums import RuleMode, RuleRisk
from .GenericWildcardPrincipalRule import GenericWildcardPrincipalRule


class PartialWildcardPrincipalRule(GenericWildcardPrincipalRule):

    REASON_WILCARD_PRINCIPAL = "{} should not allow wildcard in principals or account-wide principals (principal: '{}')"

    RULE_MODE = RuleMode.MONITOR
    RISK_VALUE = RuleRisk.MEDIUM
    """
    Will catch:

    - Principal: arn:aws:iam:12345:12345*

    """
    FULL_REGEX = re.compile(r"^arn:aws:iam::.*:(.*\*|root)$")
