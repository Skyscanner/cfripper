import pytest

from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rules.slingshot_secret_noecho import SlingshotSecretNoEchoRule
from tests.utils import compare_lists_of_failures, get_cfmodel_from


@pytest.fixture()
def good_template_with_noecho():
    return get_cfmodel_from("rules/SlingshotSecretNoEchoRule/good_template_with_noecho.yaml").resolve()


@pytest.fixture()
def bad_template_missing_noecho():
    return get_cfmodel_from("rules/SlingshotSecretNoEchoRule/bad_template_missing_noecho.yaml").resolve()


@pytest.fixture()
def bad_template_parameter_not_defined():
    return get_cfmodel_from("rules/SlingshotSecretNoEchoRule/bad_template_parameter_not_defined.yaml").resolve()


class TestSlingshotSecretNoEchoRule:
    def test_no_failures_when_noecho_is_set(self, good_template_with_noecho):
        rule = SlingshotSecretNoEchoRule(None)
        extras = {
            "stack": {
                "parameters": {
                    "DBPassword": "<SECRET:DB_PASSWORD>",
                    "OAuthClientId": "<SECRET:OAUTH_CLIENT_ID>",
                    "OAuthClientSecret": "<SECRET:OAUTH_CLIENT_SECRET>",
                    "Environment": "sandbox",
                }
            }
        }
        result = rule.invoke(good_template_with_noecho, extras)

        assert result.valid
        assert compare_lists_of_failures(result.failures, [])

    def test_failures_raised_when_noecho_missing(self, bad_template_missing_noecho):
        rule = SlingshotSecretNoEchoRule(None)
        extras = {
            "stack": {
                "parameters": {
                    "AccountId": "<SECRET:DATABRICKS_SANDBOX_ACCOUNT_ID>",
                    "OAuthClientId": "<SECRET:SANDBOX_OAUTH_CLIENT_ID>",
                    "OAuthClientSecret": "<SECRET:SANDBOX_OAUTH_CLIENT_SECRET>",
                    "Environment": "sandbox",
                }
            }
        }
        result = rule.invoke(bad_template_missing_noecho, extras)

        assert not result.valid
        assert compare_lists_of_failures(
            result.failures,
            [
                Failure(
                    granularity=RuleGranularity.STACK,
                    reason="Parameter AccountId contains a Slingshot secret but NoEcho is not set.",
                    risk_value=RuleRisk.MEDIUM,
                    rule="SlingshotSecretNoEchoRule",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids={"AccountId"},
                    resource_types=None,
                ),
                Failure(
                    granularity=RuleGranularity.STACK,
                    reason="Parameter OAuthClientId contains a Slingshot secret but NoEcho is not set.",
                    risk_value=RuleRisk.MEDIUM,
                    rule="SlingshotSecretNoEchoRule",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids={"OAuthClientId"},
                    resource_types=None,
                ),
                Failure(
                    granularity=RuleGranularity.STACK,
                    reason="Parameter OAuthClientSecret contains a Slingshot secret but NoEcho is not set.",
                    risk_value=RuleRisk.MEDIUM,
                    rule="SlingshotSecretNoEchoRule",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids={"OAuthClientSecret"},
                    resource_types=None,
                ),
            ],
        )

    def test_failure_when_parameter_not_in_template(self, bad_template_parameter_not_defined):
        rule = SlingshotSecretNoEchoRule(None)
        extras = {
            "stack": {
                "parameters": {
                    "UndefinedSecret": "<SECRET:SOME_SECRET>",
                    "Environment": "sandbox",
                }
            }
        }
        result = rule.invoke(bad_template_parameter_not_defined, extras)

        assert not result.valid
        assert compare_lists_of_failures(
            result.failures,
            [
                Failure(
                    granularity=RuleGranularity.STACK,
                    reason="Parameter UndefinedSecret contains a Slingshot secret but NoEcho is not set.",
                    risk_value=RuleRisk.MEDIUM,
                    rule="SlingshotSecretNoEchoRule",
                    rule_mode=RuleMode.BLOCKING,
                    actions=None,
                    resource_ids={"UndefinedSecret"},
                    resource_types=None,
                ),
            ],
        )

    def test_no_failures_when_no_secrets(self, good_template_with_noecho):
        rule = SlingshotSecretNoEchoRule(None)
        extras = {
            "stack": {
                "parameters": {
                    "DBPassword": "plain-password",
                    "Environment": "sandbox",
                }
            }
        }
        result = rule.invoke(good_template_with_noecho, extras)

        assert result.valid
        assert compare_lists_of_failures(result.failures, [])

    def test_no_failures_when_extras_empty(self, good_template_with_noecho):
        rule = SlingshotSecretNoEchoRule(None)

        result = rule.invoke(good_template_with_noecho, None)
        assert result.valid
        assert compare_lists_of_failures(result.failures, [])

        result = rule.invoke(good_template_with_noecho, {})
        assert result.valid
        assert compare_lists_of_failures(result.failures, [])

    def test_no_failures_when_stack_parameters_empty(self, good_template_with_noecho):
        rule = SlingshotSecretNoEchoRule(None)
        extras = {"stack": {"parameters": {}}}

        result = rule.invoke(good_template_with_noecho, extras)

        assert result.valid
        assert compare_lists_of_failures(result.failures, [])

    def test_detects_secret_in_middle_of_value(self, bad_template_missing_noecho):
        rule = SlingshotSecretNoEchoRule(None)
        extras = {
            "stack": {
                "parameters": {
                    "AccountId": "prefix-<SECRET:ACCOUNT_ID>-suffix",
                }
            }
        }
        result = rule.invoke(bad_template_missing_noecho, extras)

        assert not result.valid
        assert len(result.failures) == 1
        assert result.failures[0].resource_ids == {"AccountId"}

    def test_rule_supports_filter_config(self, bad_template_missing_noecho, default_allow_all_config):
        rule = SlingshotSecretNoEchoRule(default_allow_all_config)
        extras = {
            "stack": {
                "parameters": {
                    "AccountId": "<SECRET:DATABRICKS_SANDBOX_ACCOUNT_ID>",
                }
            }
        }
        result = rule.invoke(bad_template_missing_noecho, extras)

        assert result.valid
        assert compare_lists_of_failures(result.failures, [])
