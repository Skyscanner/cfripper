from unittest.mock import MagicMock, patch
from xml.etree import ElementTree as ET

import click
import pytest
from click.testing import CliRunner

import cfripper.cli as undertest
from cfripper.cli import format_result, format_result_junit
from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Result
from tests.utils import FIXTURE_ROOT_PATH


@pytest.mark.parametrize(
    "aws_account_id_arg, validation_result",
    [(None, None), ("", None), ("123456789012", "123456789012")],
)
def test_validate_aws_account_id(
    aws_account_id_arg,
    validation_result,
):
    fake_command = click.Command("fake_command")
    fake_context = click.Context(fake_command)
    fake_param = "fake_param"
    assert undertest.validate_aws_account_id(fake_context, fake_param, aws_account_id_arg) == validation_result


def test_validate_aws_account_id_with_malformed_arg():
    fake_command = click.Command("fake_command")
    fake_context = click.Context(fake_command)
    fake_param = "fake_param"

    with pytest.raises(click.BadParameter):
        undertest.validate_aws_account_id(fake_context, fake_param, "malformed aws account id")


@pytest.mark.parametrize(
    "aws_principals_arg, validation_result",
    [
        (None, None),
        ("", None),
        ("123456789012", ["123456789012"]),
        (
            "arn:aws:iam::123456789012:root,234567890123,arn:aws:iam::111222333444:user/user-name",
            ["arn:aws:iam::123456789012:root", "234567890123", "arn:aws:iam::111222333444:user/user-name"],
        ),
    ],
)
def test_validate_aws_principals(
    aws_principals_arg,
    validation_result,
):
    fake_command = click.Command("fake_command")
    fake_context = click.Context(fake_command)
    fake_param = "fake_param"
    assert undertest.validate_aws_principals(fake_context, fake_param, aws_principals_arg) == validation_result


@patch("cfripper.cli.process_template")
def test_aws_account_id_cli_option(patched_process_template: MagicMock):
    patched_process_template.return_value = True
    test_template_path = str(FIXTURE_ROOT_PATH) + "/others/iam_role.json"
    fake_aws_account_id = "123456789012"

    runner = CliRunner()
    result = runner.invoke(undertest.cli, ["--aws-account-id", fake_aws_account_id, test_template_path])
    assert patched_process_template.call_count == 1
    assert patched_process_template.call_args[1]["aws_account_id"] == fake_aws_account_id
    assert result.exit_code == 0


@patch("cfripper.cli.process_template")
def test_aws_principles_cli_option(patched_process_template: MagicMock):
    patched_process_template.return_value = True
    test_template_path = str(FIXTURE_ROOT_PATH) + "/others/iam_role.json"
    fake_aws_principals = ["123456789012", "234567890123"]

    runner = CliRunner()
    result = runner.invoke(undertest.cli, ["--aws-principals", ",".join(fake_aws_principals), test_template_path])
    assert patched_process_template.call_count == 1
    assert patched_process_template.call_args[1]["aws_principals"] == fake_aws_principals
    assert result.exit_code == 0


# --- JUnitXML output (#186) --------------------------------------------------


@pytest.fixture
def result_with_failures() -> Result:
    """A Result carrying one blocking failure and one monitored failure."""

    result = Result()
    result.add_failure(
        rule="PolicyOnUserRule",
        reason="IAM policy should not apply directly to users",
        rule_mode=RuleMode.BLOCKING,
        risk_value=RuleRisk.MEDIUM,
        granularity=RuleGranularity.RESOURCE,
        resource_ids={"DirectPolicy"},
        resource_types={"AWS::IAM::Policy"},
    )
    result.add_failure(
        rule="PrivilegeEscalationRule",
        reason="blacklisted IAM actions",
        rule_mode=RuleMode.MONITOR,
        risk_value=RuleRisk.HIGH,
        granularity=RuleGranularity.RESOURCE,
        actions={"iam:CreateAccessKey"},
    )
    return result


def test_format_result_junit_is_well_formed_xml(result_with_failures: Result):
    # Given a result carrying one blocking and one monitored failure.
    # When it is rendered as JUnit and re-parsed.
    xml = format_result_junit(result_with_failures, template_name="template.yaml")
    root = ET.fromstring(xml)
    cases = root.findall("testcase")
    # `Result.failures` has no documented ordering, so the names are collected
    # order-independently: asserting on the iteration order would be fragile.
    case_names = sorted(case.attrib["name"] for case in cases)
    failure_nodes = [case.find("failure") for case in cases]
    direct_policy = {case.attrib["name"]: case for case in cases}["PolicyOnUserRule"].find("failure")

    # Then the suite describes both failures.
    assert root.tag == "testsuite"
    assert root.attrib["name"] == "template.yaml"
    assert root.attrib["tests"] == "2"
    assert root.attrib["failures"] == "2"
    assert root.attrib["errors"] == "0"
    assert case_names == ["PolicyOnUserRule", "PrivilegeEscalationRule"]
    # Each case carries a <failure> child, which is what a reporter counts.
    assert all(node is not None for node in failure_nodes)
    assert direct_policy is not None
    assert direct_policy.attrib["type"] == "MEDIUM"
    # The full detail lives in the element text, not only in the message.
    assert direct_policy.text is not None
    assert "resource_ids: DirectPolicy" in direct_policy.text


def test_format_result_junit_escapes_reasons_and_resource_ids():
    """Reasons embed template fragments, so output must survive XML metacharacters.

    The report is parsed by CI tooling; a reason containing `<` or `&` must be
    escaped rather than producing invalid XML or injecting a node.
    """
    # Given a failure whose reason and resource id both carry XML
    # metacharacters and a closing tag.
    result = Result()
    result.add_failure(
        rule="SomeRule",
        reason='value <not escaped> & "quoted" </failure><injected/>',
        rule_mode=RuleMode.BLOCKING,
        risk_value=RuleRisk.HIGH,
        granularity=RuleGranularity.RESOURCE,
        resource_ids={"<weird & id>"},
    )

    # When it is rendered and re-parsed (which raises if the escaping is wrong).
    root = ET.fromstring(format_result_junit(result))
    cases = root.findall("testcase")
    injected = root.findall(".//injected")
    text = root.find("testcase").find("failure").text

    # Then the metacharacters survive as text and no node was injected.
    # The search covers the whole tree: a bare `findall("injected")` would only
    # look at direct children of the suite and miss one nested under a <testcase>.
    assert len(cases) == 1
    assert injected == []
    assert text is not None
    assert "<not escaped>" in text
    assert "<weird & id>" in text


def test_format_result_junit_reports_a_clean_template_as_zero_cases():
    # Given a result with no failures and no exceptions.
    # When it is rendered as JUnit and re-parsed.
    root = ET.fromstring(format_result_junit(Result()))
    cases = root.findall("testcase")

    # Then the suite reports nothing to run.
    assert root.attrib["tests"] == "0"
    assert root.attrib["failures"] == "0"
    assert cases == []


def test_format_result_junit_reports_exceptions_as_errors():
    """An exception is the scan failing, not a rule violation — hence <error>."""
    # Given a result carrying one exception.
    result = Result()
    result.add_exception(ValueError("could not parse template"))

    # When it is rendered as JUnit and re-parsed.
    root = ET.fromstring(format_result_junit(result))
    error = root.find("testcase").find("error")

    # Then the exception is reported as an error rather than a failure.
    assert root.attrib["errors"] == "1"
    assert root.attrib["failures"] == "0"
    assert error is not None
    assert error.attrib["type"] == "ValueError"


def test_format_result_dispatches_junit(result_with_failures: Result):
    # Given a result and the name of the JUnit format.
    # When the dispatcher renders it.
    xml = format_result(result_with_failures, "junit", template_name="t.yaml")

    # Then the JUnit renderer produced a suite named after the template.
    assert xml.startswith("<testsuite")
    assert 'name="t.yaml"' in xml


def test_cli_accepts_junit_format_and_names_the_suite_after_the_template():
    """The option reaches the formatter with the template name, through the CLI."""
    # Given the CLI invoked on a template with --format junit.
    template = FIXTURE_ROOT_PATH / "others" / "iam_policy_on_user.json"
    runner = CliRunner()
    with patch("cfripper.cli.process_template") as patched:
        patched.return_value = True
        result = runner.invoke(undertest.cli, [str(template), "--format", "junit"])
    output_format = patched.call_args[1]["output_format"]

    # Then the option reached the formatter as "junit".
    # The formatter is called with the template's file name, not its full path,
    # so a report from several templates stays readable.
    assert result.exit_code == 0, result.output
    assert output_format == "junit"
