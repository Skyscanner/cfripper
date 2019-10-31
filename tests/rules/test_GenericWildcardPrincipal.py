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
import pytest

from cfripper.config.config import Config
from cfripper.model.result import Result
from cfripper.rules.GenericWildcardPrincipalRule import GenericWildcardPrincipalRule
from tests.utils import get_cfmodel_from


@pytest.fixture()
def good_template():
    return get_cfmodel_from("rules/GenericWildcardPrincipalRule/good_template.json").resolve()


@pytest.fixture()
def bad_template():
    return get_cfmodel_from("rules/GenericWildcardPrincipalRule/bad_template.json").resolve()


def test_no_failures_are_raised(good_template):
    result = Result()
    rule = GenericWildcardPrincipalRule(None, result)
    rule.invoke(good_template)

    assert result.valid
    assert len(result.failed_rules) == 0
    assert len(result.failed_monitored_rules) == 0


def test_failures_are_raised(bad_template):
    result = Result()
    rule = GenericWildcardPrincipalRule(None, result)
    rule.invoke(bad_template)

    assert result.valid
    assert len(result.failed_rules) == 0
    assert len(result.failed_monitored_rules) == 2
    assert result.failed_monitored_rules[0].rule == "GenericWildcardPrincipalRule"
    assert (
        result.failed_monitored_rules[0].reason
        == "PolicyA should not allow wildcard in principals or account-wide principals "
        "(principal: 'somewhatrestricted:*')"
    )
    assert result.failed_monitored_rules[1].rule == "GenericWildcardPrincipalRule"
    assert (
        result.failed_monitored_rules[1].reason
        == "PolicyA should not allow wildcard in principals or account-wide principals "
        "(principal: 'arn:aws:iam::123445:*')"
    )


@pytest.fixture
def mock_rule_to_resource_whitelist():
    return {
        "GenericWildcardPrincipalRule": {
            "test_*": ["resource_5"],
            "test_stack": ["resource_1", "another_resource"],
            "other_stack": ["resource_2", "another_resource"],
            "stack_without_whitelisted_resources": [],
        },
        "OtherRuleThatUsesResourceWhitelists": {"test_stack": ["resource_3"], "other_stack": ["resource_4"]},
    }


def test_wildcard_principal_rule_is_whitelisted_retrieved_correctly(mock_rule_to_resource_whitelist):
    mock_rules = ["RuleThatUsesResourceWhitelists", "SecurityGroupOpenToWorldRule"]
    config = Config(
        stack_name="test_stack",
        rules=mock_rules,
        stack_whitelist={},
        rule_to_resource_whitelist=mock_rule_to_resource_whitelist,
    )

    wildcard_principal_rule = GenericWildcardPrincipalRule(config=config, result=None)

    assert wildcard_principal_rule.resource_is_whitelisted(logical_id="resource_1") is True
