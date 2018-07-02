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

from moto import mock_s3
from cfripper.s3_adapter import S3Adapter, InvalidURLException


@mock_s3
class TestS3Adapter:
    def set_s3_file(self, bucket, key, content):
        client = boto3.client('s3')

        try:
            client.create_bucket(Bucket=bucket)
        except:
            pass

        client.put_object(
            Bucket=bucket,
            Key=key,
            Body=content.encode('utf-8')
        )

    def test_valid_json(self):
        json_content = """
            {
                "hello": "this is valid json"
            }
        """
        bucket = 'cf-templates-1234'
        filename = 'myexamplestack.json'

        self.set_s3_file(bucket, filename, json_content)

        url = "https://s3-eu-west-1.amazonaws.com/{}/{}".format(bucket, filename)

        adapter = S3Adapter()
        result = adapter.download_template_to_dictionary(url)

        assert result['hello'] == "this is valid json"

    def test_valid_yaml(self):
        yaml_content = """
        hello: this is valid\n\r
        """

        bucket = 'cf-templates-1234'
        filename = 'myexamplestack.yml'

        self.set_s3_file(bucket, filename, yaml_content)

        url = "https://s3-eu-west-1.amazonaws.com/{}/{}".format(bucket, filename)

        adapter = S3Adapter()
        result = adapter.download_template_to_dictionary(url)

        assert result['hello'] == "this is valid"

    def test_valid_yaml_with_cf_shorthand_ref(self):
        yaml_content = """
        myprop: !Ref hello\n\r
        """

        bucket = 'cf-templates-1234'
        filename = 'myexamplestack.yml'

        self.set_s3_file(bucket, filename, yaml_content)

        url = "https://s3-eu-west-1.amazonaws.com/{}/{}".format(bucket, filename)

        adapter = S3Adapter()
        result = adapter.download_template_to_dictionary(url)

        assert result['myprop'] == {
            'Ref': 'hello'
        }

    def test_valid_yaml_with_cf_shorthand_join(self):
        yaml_content = """
        myprop: !Join ['-', ['hello', 'world']]\n\r
        """

        bucket = 'cf-templates-1234'
        filename = 'myexamplestack.yml'

        self.set_s3_file(bucket, filename, yaml_content)

        url = "https://s3-eu-west-1.amazonaws.com/{}/{}".format(bucket, filename)

        adapter = S3Adapter()
        result = adapter.download_template_to_dictionary(url)

        assert result['myprop'] == {
            'Fn::Join': ['-',
                [
                    'hello',
                    'world'
                ]
            ]
        }

    def test_valid_yaml_with_cf_getatt_array_syntax(self):
        yaml_content = """
        myprop:\n\r
            !GetAtt\n\r
                - hello\n\r
                - world\n\r
        """

        bucket = 'cf-templates-1234'
        filename = 'myexamplestack.yml'

        self.set_s3_file(bucket, filename, yaml_content)

        url = "https://s3-eu-west-1.amazonaws.com/{}/{}".format(bucket, filename)

        adapter = S3Adapter()
        result = adapter.download_template_to_dictionary(url)

        assert result['myprop'] == {
            'Fn::GetAtt': [
                'hello',
                'world'
            ]
        }

    def test_valid_yaml_with_cf_getatt_dotsyntax(self):
        yaml_content = """
        myprop: !GetAtt hello.world\n\r
        """

        bucket = 'cf-templates-1234'
        filename = 'myexamplestack.yml'

        self.set_s3_file(bucket, filename, yaml_content)

        url = "https://s3-eu-west-1.amazonaws.com/{}/{}".format(bucket, filename)

        adapter = S3Adapter()
        result = adapter.download_template_to_dictionary(url)

        assert result['myprop'] == {
            'Fn::GetAtt': [
                'hello',
                'world'
            ]
        }

    def test_parse_slingshot_support_file_url(self):
        url = "https://s3-eu-west-1.amazonaws.com/skyscanner-prod-eu-west-1-slingshot-deployment/statemachine-execution/iac/20180227114824_he6Fr31y/lambda_role.yml?Expires=1519735705&AWSAccessKeyId=ASIAJWMEHG7LG45YJUMA&Signature=A%2BW9r7RKdcVjO2C9cDI1sLCJE8c%3D&x-amz-security-token=FQoDYXdzELj%2F%2F%2F%2F%2F%2F..."

        bucket, path = S3Adapter.extract_bucket_name_and_path_from_url(url)

        assert bucket == 'skyscanner-prod-eu-west-1-slingshot-deployment'
        assert path == 'statemachine-execution/iac/20180227114824_he6Fr31y/lambda_role.yml'

    def test_invalid_format(self):
        invalid_content = """
            {
                'asdf': 'asdf'
                'asd': 'asd'
        """

        bucket = 'cf-templates-1234'
        filename = 'myexamplestack.yml'

        self.set_s3_file(bucket, filename, invalid_content)

        url = "https://s3-eu-west-1.amazonaws.com/{}/{}".format(bucket, filename)

        adapter = S3Adapter()

        assert adapter.download_template_to_dictionary(url) is None

    def test_invalid_url(self):
        url = "someweirdurl/wheretheresnoprotocol/justcoz"

        adapter = S3Adapter()

        with pytest.raises(InvalidURLException):
            result = adapter.download_template_to_dictionary(url)

    def test_url_with_path_prefix(self):
        json_content = """
            {
                "hello": "this is valid json"
            }
        """
        bucket = 'cf-templates-1234'
        filename = 'myprefixes/aaaaaa/myexamplestack.json'

        self.set_s3_file(bucket, filename, json_content)

        url = "https://s3-eu-west-1.amazonaws.com/{}/{}".format(bucket, filename)

        adapter = S3Adapter()
        result = adapter.download_template_to_dictionary(url)

        assert result['hello'] == "this is valid json"

    def test_urlencoded_url(self):
        json_content = """
            {
                "hello": "this is valid json"
            }
        """
        bucket = 'cf-templates-1234'
        filename = '2017284ltK-adfs%20iam%20role.json'

        self.set_s3_file(bucket, '2017284ltK-adfs iam role.json', json_content)

        url = "https://s3-eu-west-1.amazonaws.com/{}/{}".format(bucket, filename)

        adapter = S3Adapter()
        result = adapter.download_template_to_dictionary(url)

        assert result['hello'] == "this is valid json"
