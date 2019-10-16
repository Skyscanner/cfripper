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
import os

import pycfmodel
import pytest
from cfripper.model.enums import RuleMode, RuleRisk, RuleGranularity
from cfripper.model.rule_processor import RuleProcessor
from cfripper.model.utils import convert_json_or_yaml_to_dict
from cfripper.rules import DEFAULT_RULES

from cfripper.rules.CrossAccountTrustRule import CrossAccountTrustRule
from cfripper.config.config import Config
from cfripper.model.result import Result


@pytest.fixture()
def template_one_role():
    dir_path = os.path.dirname(os.path.realpath(__file__))
    with open(f"{dir_path}/test_templates/iam_root_role_cross_account.json") as cf_script:
        cf_template = convert_json_or_yaml_to_dict(cf_script.read())
    return pycfmodel.parse(cf_template)


@pytest.fixture()
def template_two_roles_dict():
    dir_path = os.path.dirname(os.path.realpath(__file__))
    with open(f"{dir_path}/test_templates/iam_root_role_cross_account_two_roles.json") as cf_script:
        cf_template = convert_json_or_yaml_to_dict(cf_script.read())
    return cf_template


@pytest.fixture()
def expected_result_two_roles():
    return [
        {
            "rule": "CrossAccountTrustRule",
            "reason": "RootRoleOne has forbidden cross-account trust relationship with arn:aws:iam::123456789:root",
            "rule_mode": RuleMode.BLOCKING,
            "risk_value": RuleRisk.MEDIUM,
            "resource_ids": {"RootRoleOne"},
            "actions": set(),
            "granularity": RuleGranularity.RESOURCE,
        },
        {
            "rule": "CrossAccountTrustRule",
            "reason": "RootRoleOne has forbidden cross-account trust relationship with arn:aws:iam::999999999:role/someuser@bla.com",
            "rule_mode": RuleMode.BLOCKING,
            "risk_value": RuleRisk.MEDIUM,
            "resource_ids": {"RootRoleOne"},
            "actions": set(),
            "granularity": RuleGranularity.RESOURCE,
        },
        {
            "rule": "CrossAccountTrustRule",
            "reason": "RootRoleTwo has forbidden cross-account trust relationship with arn:aws:iam::123456789:root",
            "rule_mode": RuleMode.BLOCKING,
            "risk_value": RuleRisk.MEDIUM,
            "resource_ids": {"RootRoleTwo"},
            "actions": set(),
            "granularity": RuleGranularity.RESOURCE,
        },
        {
            "rule": "CrossAccountTrustRule",
            "reason": "RootRoleTwo has forbidden cross-account trust relationship with arn:aws:iam::999999999:role/someuser@bla.com",
            "rule_mode": RuleMode.BLOCKING,
            "risk_value": RuleRisk.MEDIUM,
            "resource_ids": {"RootRoleTwo"},
            "actions": set(),
            "granularity": RuleGranularity.RESOURCE,
        },
    ]


def test_report_format_is_the_one_expected(template_one_role):
    result = Result()
    rule = CrossAccountTrustRule(Config(aws_account_id="123456789"), result)
    rule.invoke(template_one_role.resources, template_one_role.parameters)

    assert not result.valid
    assert result.failed_rules == [
        {
            "rule": "CrossAccountTrustRule",
            "reason": "RootRole has forbidden cross-account trust relationship with arn:aws:iam::123456789:root",
            "rule_mode": RuleMode.BLOCKING,
            "risk_value": RuleRisk.MEDIUM,
            "resource_ids": {"RootRole"},
            "actions": set(),
            "granularity": RuleGranularity.RESOURCE,
        },
        {
            "rule": "CrossAccountTrustRule",
            "reason": (
                "RootRole has forbidden cross-account trust relationship with arn:aws:iam::999999999:role/"
                "someuser@bla.com"
            ),
            "rule_mode": RuleMode.BLOCKING,
            "risk_value": RuleRisk.MEDIUM,
            "resource_ids": {"RootRole"},
            "actions": set(),
            "granularity": RuleGranularity.RESOURCE,
        },
    ]


def test_resource_whitelisting_works_as_expected(template_two_roles_dict, expected_result_two_roles):
    result = Result()
    mock_rule_to_resource_whitelist = {"CrossAccountTrustRule": {".*": {"RootRoleOne"}}}
    mock_config = Config(
        rules=["CrossAccountTrustRule"],
        aws_account_id="123456789",
        rule_to_resource_whitelist=mock_rule_to_resource_whitelist,
        stack_name="mockstack",
        stack_whitelist={},
    )
    rules = [DEFAULT_RULES.get(rule)(mock_config, result) for rule in mock_config.rules]
    processor = RuleProcessor(*rules)
    processor.process_cf_template(template_two_roles_dict, mock_config, result)

    assert not result.valid
    assert result.failed_rules == expected_result_two_roles[-2:]


def test_whitelisted_stacks_do_not_report_anything(template_two_roles_dict):
    result = Result()
    mock_stack_whitelist = {"mockstack": ["CrossAccountTrustRule"]}
    mock_config = Config(
        rules=["CrossAccountTrustRule"],
        aws_account_id="123456789",
        stack_name="mockstack",
        stack_whitelist=mock_stack_whitelist,
    )
    rules = [DEFAULT_RULES.get(rule)(mock_config, result) for rule in mock_config.rules]
    processor = RuleProcessor(*rules)
    processor.process_cf_template(template_two_roles_dict, mock_config, result)

    assert result.valid


def test_non_whitelisted_stacks_are_reported_normally(template_two_roles_dict, expected_result_two_roles):
    result = Result()
    mock_stack_whitelist = {"mockstack": ["CrossAccountTrustRule"]}
    mock_config = Config(
        rules=["CrossAccountTrustRule"],
        aws_account_id="123456789",
        stack_name="anotherstack",
        stack_whitelist=mock_stack_whitelist,
    )
    rules = [DEFAULT_RULES.get(rule)(mock_config, result) for rule in mock_config.rules]
    processor = RuleProcessor(*rules)
    processor.process_cf_template(template_two_roles_dict, mock_config, result)
    assert not result.valid
    assert result.failed_rules == expected_result_two_roles
