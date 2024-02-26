import json
from unittest.mock import call, patch

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from cfripper.boto3_client import Boto3Client
from cfripper.model.utils import InvalidURLException, convert_json_or_yaml_to_dict

CLIENT_ERROR_ACCESS_DENIED = ClientError({"Error": {"Code": "AccessDenied"}}, "list_exports")
CLIENT_ERROR_THROTTLING = ClientError({"Error": {"Code": "Throttling"}}, "get_template")
CLIENT_ERROR_VALIDATION = ClientError({"Error": {"Code": "ValidationError"}}, "get_template")
DUMMY_CLIENT_ERROR = ClientError({"Error": {"Code": "Exception"}}, "get_template")

TEST_BUCKET_NAME = "megabucket"


@pytest.fixture
def s3_bucket(default_aws_region):
    with mock_aws():
        boto3.client("s3").create_bucket(
            Bucket=TEST_BUCKET_NAME, CreateBucketConfiguration={"LocationConstraint": default_aws_region}
        )
        yield boto3.resource("s3").Bucket(TEST_BUCKET_NAME)


@pytest.fixture
def boto3_client(default_aws_region):
    with mock_aws():
        yield Boto3Client("123456789", default_aws_region, "stack-id")


@pytest.mark.parametrize(
    "aws_responses, expected_template, mocked_info_logs, mocked_warning_logs, mocked_exceptions",
    [
        ([{"A": "a"}], {"A": "a"}, [call("Stack: stack-id on 123456789 - eu-west-1 get_template Attempt #0")], [], []),
        (
            [None, {"A": "a"}],
            {"A": "a"},
            [call(f"Stack: stack-id on 123456789 - eu-west-1 get_template Attempt #{i}") for i in range(2)],
            [call("No template body found for stack: stack-id on 123456789 - eu-west-1")],
            [],
        ),
        (
            [CLIENT_ERROR_VALIDATION],
            None,
            [call("Stack: stack-id on 123456789 - eu-west-1 get_template Attempt #0")],
            [call("There is no stack: stack-id on 123456789 - eu-west-1")],
            [],
        ),
        (
            [CLIENT_ERROR_THROTTLING, {"A": "a"}],
            {"A": "a"},
            [call(f"Stack: stack-id on 123456789 - eu-west-1 get_template Attempt #{i}") for i in range(2)],
            [call("AWS Throttling: stack-id on 123456789 - eu-west-1")],
            [],
        ),
        (
            [DUMMY_CLIENT_ERROR, {"A": "a"}],
            {"A": "a"},
            [call(f"Stack: stack-id on 123456789 - eu-west-1 get_template Attempt #{i}") for i in range(2)],
            [],
            [call("Unexpected error occurred when getting stack template for: stack-id on 123456789 - eu-west-1")],
        ),
        (
            ['{"A": "a"}'],
            {"A": "a"},
            [call("Stack: stack-id on 123456789 - eu-west-1 get_template Attempt #0")],
            [],
            [],
        ),
        (["A: a"], {"A": "a"}, [call("Stack: stack-id on 123456789 - eu-west-1 get_template Attempt #0")], [], []),
    ],
)
@patch("logging.Logger.info")
@patch("logging.Logger.warning")
@patch("logging.Logger.exception")
def test_get_template(
    patched_exceptions,
    patched_logger_warning,
    patched_logger_info,
    aws_responses,
    expected_template,
    mocked_info_logs,
    mocked_warning_logs,
    mocked_exceptions,
    boto3_client,
):
    with patch.object(boto3_client, "session") as session_mock:
        session_mock.client().get_template().get.side_effect = aws_responses
        template = boto3_client.get_template()
        assert template == expected_template
    assert patched_logger_info.mock_calls == mocked_info_logs
    assert patched_logger_warning.mock_calls == mocked_warning_logs
    assert patched_exceptions.mock_calls == mocked_exceptions


def test_valid_json(s3_bucket, boto3_client):
    filename = "myexamplestack.json"
    json_content = """
        {
            "hello": "this is valid json"
        }
    """
    s3_bucket.put_object(Key=filename, Body=json_content.encode("utf-8"))

    result = boto3_client.download_template_to_dictionary(
        f"https://s3-eu-west-1.amazonaws.com/{TEST_BUCKET_NAME}/{filename}"
    )
    assert result["hello"] == "this is valid json"


def test_valid_yaml(s3_bucket, boto3_client):
    filename = "myexamplestack.yml"
    yaml_content = """
        hello: this is valid\n\r
    """
    s3_bucket.put_object(Key=filename, Body=yaml_content.encode("utf-8"))

    result = boto3_client.download_template_to_dictionary(
        f"https://s3-eu-west-1.amazonaws.com/{TEST_BUCKET_NAME}/{filename}"
    )
    assert result["hello"] == "this is valid"


def test_valid_yaml_as_bytes():
    result = convert_json_or_yaml_to_dict(bytes("hello: this is valid", "utf8"))
    assert result["hello"] == "this is valid"


@patch("logging.Logger.exception")
def test_invalid_yaml_as_bytes(patched_logger):
    result = convert_json_or_yaml_to_dict(bytes("Abc: g\nh:f", "utf8"), "bad-stack")
    assert result is None
    patched_logger.assert_called_once_with("Could not parse JSON template for bad-stack")


def test_valid_yaml_with_cf_shorthand_ref(s3_bucket, boto3_client):
    filename = "myexamplestack.yml"
    yaml_content = """
    myprop: !Ref hello\n\r
    """
    s3_bucket.put_object(Key=filename, Body=yaml_content.encode("utf-8"))

    result = boto3_client.download_template_to_dictionary(
        f"https://s3-eu-west-1.amazonaws.com/{TEST_BUCKET_NAME}/{filename}"
    )
    assert result["myprop"] == {"Ref": "hello"}


def test_valid_yaml_with_cf_shorthand_join(s3_bucket, boto3_client):
    filename = "myexamplestack.yml"
    yaml_content = """
    myprop: !Join ['-', ['hello', 'world']]\n\r
    """
    s3_bucket.put_object(Key=filename, Body=yaml_content.encode("utf-8"))

    result = boto3_client.download_template_to_dictionary(
        f"https://s3-eu-west-1.amazonaws.com/{TEST_BUCKET_NAME}/{filename}"
    )
    assert result["myprop"] == {"Fn::Join": ["-", ["hello", "world"]]}


def test_valid_yaml_with_cf_getatt_array_syntax(s3_bucket, boto3_client):
    filename = "myexamplestack.yml"
    yaml_content = """
    myprop:\n\r
        !GetAtt\n\r
            - hello\n\r
            - world\n\r
    """
    s3_bucket.put_object(Key=filename, Body=yaml_content.encode("utf-8"))

    result = boto3_client.download_template_to_dictionary(
        f"https://s3-eu-west-1.amazonaws.com/{TEST_BUCKET_NAME}/{filename}"
    )
    assert result["myprop"] == {"Fn::GetAtt": ["hello", "world"]}


def test_valid_yaml_with_cf_getatt_dotsyntax(s3_bucket, boto3_client):
    filename = "myexamplestack.yml"
    yaml_content = """
    myprop: !GetAtt hello.world\n\r
    """
    s3_bucket.put_object(Key=filename, Body=yaml_content.encode("utf-8"))

    result = boto3_client.download_template_to_dictionary(
        f"https://s3-eu-west-1.amazonaws.com/{TEST_BUCKET_NAME}/{filename}"
    )
    assert result["myprop"] == {"Fn::GetAtt": ["hello", "world"]}


def test_invalid_format(s3_bucket, boto3_client):
    filename = "myexamplestack.yml"
    invalid_content = """
        {
            'asdf': 'asdf'
            'asd': 'asd'
    """
    s3_bucket.put_object(Key=filename, Body=invalid_content.encode("utf-8"))

    assert (
        boto3_client.download_template_to_dictionary(
            f"https://s3-eu-west-1.amazonaws.com/{TEST_BUCKET_NAME}/{filename}"
        )
        is None
    )


def test_invalid_url(boto3_client):
    url = "someweirdurl/wheretheresnoprotocol/justcoz"

    with pytest.raises(InvalidURLException):
        boto3_client.download_template_to_dictionary(url)


def test_url_with_path_prefix(s3_bucket, boto3_client):
    filename = "myprefixes/aaaaaa/myexamplestack.json"
    json_content = """
        {
            "hello": "this is valid json"
        }
    """
    s3_bucket.put_object(Key=filename, Body=json_content.encode("utf-8"))

    result = boto3_client.download_template_to_dictionary(
        f"https://s3-eu-west-1.amazonaws.com/{TEST_BUCKET_NAME}/{filename}"
    )
    assert result["hello"] == "this is valid json"


def test_urlencoded_url(s3_bucket, boto3_client):
    filename = "2017284ltK-adfs iam role.json"
    expected_filename = "2017284ltK-adfs iam role.json"
    json_content = """
        {
            "hello": "this is valid json"
        }
    """
    s3_bucket.put_object(Key=filename, Body=json_content.encode("utf-8"))

    result = boto3_client.download_template_to_dictionary(
        f"https://s3-eu-west-1.amazonaws.com/{TEST_BUCKET_NAME}/{expected_filename}"
    )
    assert result["hello"] == "this is valid json"


@pytest.mark.parametrize(
    "aws_responses, expected_exports, mocked_warning_logs, mocked_exceptions",
    [
        (
            [[{"Name": "A", "Value": "a"}]],
            {"A": "a"},
            [],
            [],
        ),
        (
            [[{"Foo": "Bar"}], [{"Name": "A", "Value": "a"}]],
            {"A": "a"},
            [],
            [call("Unknown exception getting AWS Export values! (123456789 - eu-west-1)")],
        ),
        (
            [CLIENT_ERROR_ACCESS_DENIED],
            {},
            [call("Access Denied for obtaining AWS Export values! (123456789 - eu-west-1)")],
            [],
        ),
        (
            [CLIENT_ERROR_THROTTLING, [{"Name": "A", "Value": "a"}]],
            {"A": "a"},
            [call("AWS Throttling: stack-id on 123456789 - eu-west-1")],
            [],
        ),
        (
            [DUMMY_CLIENT_ERROR, [{"Name": "A", "Value": "a"}]],
            {"A": "a"},
            [],
            [call("Unhandled ClientError getting AWS Export values! (123456789 - eu-west-1)")],
        ),
    ],
)
@patch("logging.Logger.warning")
@patch("logging.Logger.exception")
def test_get_exports(
    patched_exceptions,
    patched_logger_warning,
    aws_responses,
    expected_exports,
    mocked_warning_logs,
    mocked_exceptions,
    boto3_client,
):
    with patch.object(boto3_client, "session") as session_mock:
        session_mock.client().list_exports().get.side_effect = aws_responses
        exports = boto3_client.get_exports()
        assert exports == expected_exports
    assert patched_logger_warning.mock_calls == mocked_warning_logs
    assert patched_exceptions.mock_calls == mocked_exceptions


@mock_aws
def test_export_values(boto3_client: Boto3Client):
    cf_client = boto3_client.session.client("cloudformation", "eu-west-1")
    cf_client.create_stack(
        StackName="Test-Stack",
        TemplateBody=json.dumps(
            {
                "AWSTemplateFormatVersion": "2010-09-09",
                "Resources": {"MyQueue": {"Type": "AWS::SQS::Queue", "Properties": {}}},
                "Outputs": {
                    "QueueARN": {
                        "Description": "ARN of newly created SQS Queue",
                        "Value": {"Fn::GetAtt": ["MyQueue", "Arn"]},
                        "Export": {"Name": "MainQueue"},
                    },
                },
            }
        ),
    )

    # actual suffix changes between tests
    export_values = boto3_client.get_exports()
    assert len(export_values) == 1
    assert "arn:aws:sqs:eu-west-1:123456789:Test-Stack-MyQueue-" in export_values["MainQueue"]
