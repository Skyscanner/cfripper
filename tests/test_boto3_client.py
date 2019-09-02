"""
Copyright 2018 Skyscanner Ltd

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
import boto3

from unittest.mock import patch

from botocore.exceptions import ClientError
from moto import mock_s3, mock_sts

from cfripper.model.utils import (
    convert_json_or_yaml_to_dict,
    extract_bucket_name_and_path_from_url,
    InvalidURLException,
)
from cfripper.boto3_client import Boto3Client

DUMMY_CLIENT_ERROR = ClientError({"Error": {"Code": "Exception"}}, "get_template")


@mock_s3
@mock_sts
class TestBoto3Client:
    def set_s3_file(self, bucket, key, content):
        client = boto3.client("s3")

        try:
            client.create_bucket(Bucket=bucket)
        except Exception:
            pass

        client.put_object(Bucket=bucket, Key=key, Body=content.encode("utf-8"))

    @pytest.mark.parametrize(
        "aws_responses, expected_template",
        [
            (["nice template"], "nice template"),
            ([DUMMY_CLIENT_ERROR] * 10, None),
            ([DUMMY_CLIENT_ERROR, "nice template"], "nice template"),
        ],
    )
    def test_get_template(self, aws_responses, expected_template):
        adapter = Boto3Client("123456789", "eu-west-1", "stack-id")
        with patch.object(adapter, "session") as session_mock:
            session_mock.client().get_template().get.side_effect = aws_responses
            template = adapter.get_template()
            assert template == expected_template

    def test_valid_json(self):
        json_content = """
            {
                "hello": "this is valid json"
            }
        """
        bucket = "cf-templates-1234"
        filename = "myexamplestack.json"

        self.set_s3_file(bucket, filename, json_content)

        url = f"https://s3-eu-west-1.amazonaws.com/{bucket}/{filename}"

        adapter = Boto3Client("123456789", "eu-west-1", "stack-id")
        result = adapter.download_template_to_dictionary(url)

        assert result["hello"] == "this is valid json"

    def test_valid_yaml(self):
        yaml_content = """
        hello: this is valid\n\r
        """

        bucket = "cf-templates-1234"
        filename = "myexamplestack.yml"

        self.set_s3_file(bucket, filename, yaml_content)

        url = f"https://s3-eu-west-1.amazonaws.com/{bucket}/{filename}"

        adapter = Boto3Client("123456789", "eu-west-1", "stack-id")
        result = adapter.download_template_to_dictionary(url)

        assert result["hello"] == "this is valid"

    def test_valid_yaml_as_bytes(self):
        yaml_content = bytes("hello: this is valid", "utf8")

        result = convert_json_or_yaml_to_dict(yaml_content)

        assert result["hello"] == "this is valid"

    def test_valid_yaml_with_cf_shorthand_ref(self):
        yaml_content = """
        myprop: !Ref hello\n\r
        """

        bucket = "cf-templates-1234"
        filename = "myexamplestack.yml"

        self.set_s3_file(bucket, filename, yaml_content)

        url = f"https://s3-eu-west-1.amazonaws.com/{bucket}/{filename}"

        adapter = Boto3Client("123456789", "eu-west-1", "stack-id")
        result = adapter.download_template_to_dictionary(url)

        assert result["myprop"] == {"Ref": "hello"}

    def test_valid_yaml_with_cf_shorthand_join(self):
        yaml_content = """
        myprop: !Join ['-', ['hello', 'world']]\n\r
        """

        bucket = "cf-templates-1234"
        filename = "myexamplestack.yml"

        self.set_s3_file(bucket, filename, yaml_content)

        url = f"https://s3-eu-west-1.amazonaws.com/{bucket}/{filename}"

        adapter = Boto3Client("123456789", "eu-west-1", "stack-id")
        result = adapter.download_template_to_dictionary(url)

        assert result["myprop"] == {"Fn::Join": ["-", ["hello", "world"]]}

    def test_valid_yaml_with_cf_getatt_array_syntax(self):
        yaml_content = """
        myprop:\n\r
            !GetAtt\n\r
                - hello\n\r
                - world\n\r
        """

        bucket = "cf-templates-1234"
        filename = "myexamplestack.yml"

        self.set_s3_file(bucket, filename, yaml_content)

        url = f"https://s3-eu-west-1.amazonaws.com/{bucket}/{filename}"

        adapter = Boto3Client("123456789", "eu-west-1", "stack-id")
        result = adapter.download_template_to_dictionary(url)

        assert result["myprop"] == {"Fn::GetAtt": ["hello", "world"]}

    def test_valid_yaml_with_cf_getatt_dotsyntax(self):
        yaml_content = """
        myprop: !GetAtt hello.world\n\r
        """

        bucket = "cf-templates-1234"
        filename = "myexamplestack.yml"

        self.set_s3_file(bucket, filename, yaml_content)

        url = f"https://s3-eu-west-1.amazonaws.com/{bucket}/{filename}"

        adapter = Boto3Client("123456789", "eu-west-1", "stack-id")
        result = adapter.download_template_to_dictionary(url)

        assert result["myprop"] == {"Fn::GetAtt": ["hello", "world"]}

    def test_invalid_format(self):
        invalid_content = """
            {
                'asdf': 'asdf'
                'asd': 'asd'
        """

        bucket = "cf-templates-1234"
        filename = "myexamplestack.yml"

        self.set_s3_file(bucket, filename, invalid_content)

        url = f"https://s3-eu-west-1.amazonaws.com/{bucket}/{filename}"

        adapter = Boto3Client("123456789", "eu-west-1", "stack-id")

        assert adapter.download_template_to_dictionary(url) is None

    def test_invalid_url(self):
        url = "someweirdurl/wheretheresnoprotocol/justcoz"

        adapter = Boto3Client("123456789", "eu-west-1", "stack-id")

        with pytest.raises(InvalidURLException):
            adapter.download_template_to_dictionary(url)

    def test_url_with_path_prefix(self):
        json_content = """
            {
                "hello": "this is valid json"
            }
        """
        bucket = "cf-templates-1234"
        filename = "myprefixes/aaaaaa/myexamplestack.json"

        self.set_s3_file(bucket, filename, json_content)

        url = f"https://s3-eu-west-1.amazonaws.com/{bucket}/{filename}"

        adapter = Boto3Client("123456789", "eu-west-1", "stack-id")
        result = adapter.download_template_to_dictionary(url)

        assert result["hello"] == "this is valid json"

    def test_urlencoded_url(self):
        json_content = """
            {
                "hello": "this is valid json"
            }
        """
        bucket = "cf-templates-1234"
        filename = "2017284ltK-adfs%20iam%20role.json"

        self.set_s3_file(bucket, "2017284ltK-adfs iam role.json", json_content)

        url = f"https://s3-eu-west-1.amazonaws.com/{bucket}/{filename}"

        adapter = Boto3Client("123456789", "eu-west-1", "stack-id")
        result = adapter.download_template_to_dictionary(url)

        assert result["hello"] == "this is valid json"
