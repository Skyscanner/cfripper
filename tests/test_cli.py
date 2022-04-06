from unittest.mock import MagicMock, patch

import click
import pytest
from click.testing import CliRunner

import cfripper.cli as undertest
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
