import logging
from datetime import datetime
from time import sleep
from typing import Dict, Optional

import boto3
from botocore.exceptions import ClientError

from .model.utils import convert_json_or_yaml_to_dict, extract_bucket_name_and_path_from_url

logger = logging.getLogger(__file__)


class Boto3Client:
    N_RETRIES = 5

    def __init__(self, account_id, region, stack_id):
        if not account_id or not region or not stack_id:
            raise Exception(f"Missing account_id or region: (Account: {account_id} - Region: {region})")

        arn = f"arn:aws:iam::{account_id}:role/cfripper-access"
        logger.info(f"Preparing to assume role: {arn}")

        client = boto3.client("sts")
        now = datetime.utcnow().isoformat().replace(":", ".")
        role_session_name = f"CfRipper{now}{stack_id.replace(':', '.')}"[:64]  # Limit of 64 chars
        response = client.assume_role(RoleArn=arn, RoleSessionName=role_session_name)
        self.session = boto3.Session(
            aws_access_key_id=response["Credentials"]["AccessKeyId"],
            aws_secret_access_key=response["Credentials"]["SecretAccessKey"],
            aws_session_token=response["Credentials"]["SessionToken"],
        )
        self.account_id = account_id
        self.region = region
        self.stack_id = stack_id

    def get_template(self) -> Optional[Dict]:
        client = self.session.client("cloudformation", region_name=self.region)
        stack_content = None
        i = 0
        while not stack_content and i < self.N_RETRIES:
            logger.info(f"Stack: {self.stack_id} on {self.account_id} - {self.region} get_template Attempt #{i}")
            try:
                response = client.get_template(StackName=self.stack_id)
                stack_content = response.get("TemplateBody")
                if not stack_content:
                    logger.warning(
                        f"No template body found for stack: {self.stack_id} on {self.account_id} - {self.region}"
                    )
                    sleep(i)
            except ClientError as e:
                if e.response["Error"]["Code"] == "ValidationError":
                    logger.exception(f"There is no stack: {self.stack_id} on {self.account_id} - {self.region}")
                else:
                    logger.exception(
                        "Unexpected error occured when getting stack template for:"
                        f" {self.stack_id} on {self.account_id} - {self.region}"
                    )
            i += 1
        # Fix when AWS doesn't return a dict
        # https://github.com/boto/botocore/issues/1058
        # https://github.com/boto/boto3/issues/1468
        return convert_json_or_yaml_to_dict(stack_content) if isinstance(stack_content, str) else stack_content

    def download_template_to_dictionary(self, s3_url):
        """
        Download a CloudFormation template from S3 into a Dictionary.

        :param s3_url: The URL to download from.
        :return: Dictionary version of the CF Template.
        """
        bucket_name, file_path = extract_bucket_name_and_path_from_url(s3_url)

        client = self.session.client("s3", region_name=self.region)
        response = client.get_object(Bucket=bucket_name, Key=file_path)
        file_contents = response["Body"].read().decode("utf-8")

        return convert_json_or_yaml_to_dict(file_contents)
