from unittest.mock import patch

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_s3, mock_sts

from cfripper.boto3_client import Boto3Client
from cfripper.model.utils import InvalidURLException, convert_json_or_yaml_to_dict

DUMMY_CLIENT_ERROR = ClientError({"Error": {"Code": "Exception"}}, "get_template")

TEST_BUCKET_NAME = "megabucket"


@pytest.fixture
def s3_bucket():
    with mock_s3():
        boto3.client("s3").create_bucket(Bucket=TEST_BUCKET_NAME)
        yield boto3.resource("s3").Bucket(TEST_BUCKET_NAME)


@pytest.fixture
def boto3_client():
    with mock_sts():
        yield Boto3Client("123456789", "eu-west-1", "stack-id")


@pytest.mark.parametrize(
    "aws_responses, expected_template",
    [
        ([{"A": "a"}], {"A": "a"}),
        ([DUMMY_CLIENT_ERROR] * 10, None),
        ([DUMMY_CLIENT_ERROR, {"A": "a"}], {"A": "a"}),
        (['{"A": "a"}'], {"A": "a"}),
        (["A: a"], {"A": "a"}),
    ],
)
def test_get_template(aws_responses, expected_template, boto3_client):
    with patch.object(boto3_client, "session") as session_mock:
        session_mock.client().get_template().get.side_effect = aws_responses
        template = boto3_client.get_template()
        assert template == expected_template


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
