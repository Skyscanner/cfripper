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


def _result_with_failures():
    """Build a Result carrying one blocking failure and one monitored failure."""

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


def test_format_result_junit_is_well_formed_xml():
    xml = format_result_junit(_result_with_failures(), template_name="template.yaml")
    root = ET.fromstring(xml)

    assert root.tag == "testsuite"
    assert root.attrib["name"] == "template.yaml"
    assert root.attrib["tests"] == "2"
    assert root.attrib["failures"] == "2"
    assert root.attrib["errors"] == "0"

    cases = root.findall("testcase")
    # `Result.failures` has no documented ordering, so compare order-independently:
    # asserting on a list here would fail if the implementation ever changed the
    # order it iterates failures in.
    assert sorted(c.attrib["name"] for c in cases) == ["PolicyOnUserRule", "PrivilegeEscalationRule"]
    # Each case carries a <failure> child, which is what a reporter counts.
    assert all(c.find("failure") is not None for c in cases)
    by_name = {c.attrib["name"]: c for c in cases}
    direct_policy = by_name["PolicyOnUserRule"].find("failure")
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
    result = Result()
    result.add_failure(
        rule="SomeRule",
        reason='value <not escaped> & "quoted" </failure><injected/>',
        rule_mode=RuleMode.BLOCKING,
        risk_value=RuleRisk.HIGH,
        granularity=RuleGranularity.RESOURCE,
        resource_ids={"<weird & id>"},
    )

    xml = format_result_junit(result)
    root = ET.fromstring(xml)  # raises if the escaping is wrong

    assert len(root.findall("testcase")) == 1
    # No injected element from the reason text, anywhere in the tree: a bare
    # `findall("injected")` would only look at direct children of the suite and
    # miss a node injected under a <testcase>.
    assert root.findall(".//injected") == []
    text = root.find("testcase").find("failure").text
    assert "<not escaped>" in text
    assert "<weird & id>" in text


def test_format_result_junit_reports_a_clean_template_as_zero_cases():
    root = ET.fromstring(format_result_junit(Result()))

    assert root.attrib["tests"] == "0"
    assert root.attrib["failures"] == "0"
    assert root.findall("testcase") == []


def test_format_result_junit_reports_exceptions_as_errors():
    """An exception is the scan failing, not a rule violation — hence <error>."""
    result = Result()
    result.add_exception(ValueError("could not parse template"))

    root = ET.fromstring(format_result_junit(result))

    assert root.attrib["errors"] == "1"
    assert root.attrib["failures"] == "0"
    assert root.find("testcase").find("error").attrib["type"] == "ValueError"


def test_format_result_dispatches_junit():
    xml = format_result(_result_with_failures(), "junit", template_name="t.yaml")
    assert xml.startswith("<testsuite")
    assert 'name="t.yaml"' in xml


def test_cli_accepts_junit_format_and_names_the_suite_after_the_template(tmp_path):
    """The option reaches the formatter with the template name, through the CLI."""
    template = FIXTURE_ROOT_PATH / "others" / "iam_policy_on_user.json"
    runner = CliRunner()
    with patch("cfripper.cli.process_template") as patched:
        patched.return_value = True
        result = runner.invoke(undertest.cli, [str(template), "--format", "junit"])

    assert result.exit_code == 0, result.output
    # The formatter is called with the template's file name, not its full path,
    # so a report from several templates stays readable.
    assert patched.call_args[1]["output_format"] == "junit"
