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
from cfripper.rules.iam_roles import IAMRoleWildcardActionOnPolicyRule
from tests.utils import get_cfmodel_from


@pytest.fixture()
def iam_role_with_wildcard_action():
    return get_cfmodel_from("rules/IAMRoleWildcardActionOnPolicyRule/iam_role_with_wildcard_action.json").resolve()


@pytest.fixture()
def iam_role_with_wildcard_action_on_trust():
    return get_cfmodel_from(
        "rules/IAMRoleWildcardActionOnPolicyRule/iam_role_with_wildcard_action_on_trust.json"
    ).resolve()


@pytest.fixture()
def iam_managed_policy_bad_template():
    return get_cfmodel_from(
        "rules/IAMManagedPolicyWildcardActionRule/iam_managed_policy_with_wildcard_action.json"
    ).resolve()


def test_valid_iam_policy_permissions(iam_role_with_wildcard_action):
    result = Result()
    rule = IAMRoleWildcardActionOnPolicyRule(None, result)
    rule.invoke(iam_role_with_wildcard_action)

    assert result.valid
    assert len(result.failed_rules) == 0
    assert len(result.failed_monitored_rules) == 1
    assert result.failed_monitored_rules[0].rule == "IAMRoleWildcardActionOnPolicyRule"
    assert (
        result.failed_monitored_rules[0].reason
        == "IAM role WildcardActionRole should not allow a `*` action on its policy root"
    )


def test_valid_iam_policy_trust(iam_role_with_wildcard_action_on_trust):
    result = Result()
    rule = IAMRoleWildcardActionOnPolicyRule(None, result)
    rule.invoke(iam_role_with_wildcard_action_on_trust)

    assert result.valid
    assert len(result.failed_rules) == 0
    assert len(result.failed_monitored_rules) == 1
    assert result.failed_monitored_rules[0].rule == "IAMRoleWildcardActionOnPolicyRule"
    assert (
        result.failed_monitored_rules[0].reason
        == "IAM role WildcardActionRole should not allow a `*` action on its policy AssumeRolePolicy"
    )


def test_invalid_managed_policy_template(iam_managed_policy_bad_template):
    result = Result()
    rule = IAMRoleWildcardActionOnPolicyRule(Config(aws_account_id="123456789"), result)

    rule.invoke(iam_managed_policy_bad_template)

    assert result.valid
    assert len(result.failed_rules) == 0
    assert len(result.failed_monitored_rules) == 1
    assert result.failed_monitored_rules[0].rule == "IAMRoleWildcardActionOnPolicyRule"
    assert (
        result.failed_monitored_rules[0].reason
        == "IAM role CreateTestDBPolicy3 should not allow a `*` action on its AWS::IAM::ManagedPolicy "
    )
