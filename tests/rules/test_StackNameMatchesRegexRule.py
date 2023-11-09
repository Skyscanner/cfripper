import pytest
from pycfmodel.model.cf_model import CFModel

from cfripper.config.config import Config
from cfripper.rules import StackNameMatchesRegexRule


@pytest.mark.parametrize(
    "stack_name, expected_result",
    [
        ("justlowercase", True),
        ("lowercase-with-hyphens", True),
        ("lowercaseANDUPPERCASE", True),
        ("lowercase-AND-UPPERCASE-with-hyphens", True),
        ("including_underscore", False),
        ("including space", False),
        ("including-other-symbols!@£$%^&*()", False),
    ],
)
def test_stack_name_matches_regex(stack_name, expected_result):
    rule = StackNameMatchesRegexRule(Config(stack_name=stack_name, rules=["StackNameMatchesRegexRule"]))
    assert rule._stack_name_matches_regex(stack_name) == expected_result


def test_works_with_extras():
    rule = StackNameMatchesRegexRule(Config(stack_name="some-valid-stack-name", rules=["StackNameMatchesRegexRule"]))
    extras = {"stack": {"tags": [{"key": "project", "value": "some_project"}]}}
    result = rule.invoke(cfmodel=CFModel(), extras=extras)
    assert result.valid


def test_failure_is_added_for_invalid_stack_name():
    rule = StackNameMatchesRegexRule(Config(stack_name="some_invalid_stack_name", rules=["StackNameMatchesRegexRule"]))
    result = rule.invoke(cfmodel=CFModel())
    assert result.failures
    assert (
        result.failures[0].reason
        == "The stack name some_invalid_stack_name does not follow the naming convention (only alphanumerical characters and hyphens allowed)."
    )