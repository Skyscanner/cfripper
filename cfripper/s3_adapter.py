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
import json
from io import StringIO
from urllib import parse

import boto3

from cfripper.cfn_flip import to_json
from cfripper.cfn_flip.custom_yaml import custom_yaml
from cfripper.config.logger import get_logger

logger = get_logger()


class InvalidURLException(Exception):
    pass


class S3Adapter:

    def download_template_to_dictionary(self, s3_url):
        """
        Download a CloudFormation template from S3 into a Dictionary.

        :param s3_url: The URL to download from.
        :return: Dictionary version of the CF Template.
        """
        bucket_name, file_path = self.extract_bucket_name_and_path_from_url(s3_url)

        client = boto3.client("s3")
        response = client.get_object(
            Bucket=bucket_name,
            Key=file_path
        )
        file_contents = response["Body"].read().decode("utf-8")

        return self.convert_json_or_yaml_to_dict(file_contents)

    @staticmethod
    def extract_bucket_name_and_path_from_url(url):
        url = parse.urlparse(parse.unquote(url))

        if url.scheme != "https":
            raise InvalidURLException("Url does not start with 'https://' :  {}".format(url))

        _, bucket_name, *path_sections = url.path.split("/") if not url.netloc.endswith("s3.amazonaws.com") else ["", url.netloc.rsplit(".", 3)[0]] + url.path.split("/")[1:]
        path_to_file = "/".join(path_sections)

        return bucket_name, path_to_file

    @staticmethod
    def strip_shorthand_from_yaml(yaml):
        return to_json(StringIO(yaml))

    def convert_json_or_yaml_to_dict(self, file_contents):
        try:
            return json.loads(file_contents)
        except (TypeError, json.JSONDecodeError):
            pass

        try:
            return json.loads(self.strip_shorthand_from_yaml(file_contents))
        except custom_yaml.YAMLError as err:
            return None
