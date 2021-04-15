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
                    sleep((i + 1) * 2)
            except ClientError as e:
                if e.response["Error"]["Code"] == "ValidationError":
                    logger.warning(f"There is no stack: {self.stack_id} on {self.account_id} - {self.region}")
                    return stack_content
                elif e.response["Error"]["Code"] == "Throttling":
                    logger.warning(f"AWS Throttling: {self.stack_id} on {self.account_id} - {self.region}")
                    sleep((i + 1) * 2)
                else:
                    logger.exception(
                        "Unexpected error occurred when getting stack template for:"
                        f" {self.stack_id} on {self.account_id} - {self.region}"
                    )
            i += 1
        # Fix when AWS doesn't return a dict
        # https://github.com/boto/botocore/issues/1058
        # https://github.com/boto/boto3/issues/1468
        return (
            convert_json_or_yaml_to_dict(stack_content, self.stack_id)
            if isinstance(stack_content, str)
            else stack_content
        )

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

    def get_exports(self) -> Dict[str, str]:
        client = self.session.client("cloudformation", region_name=self.region)
        export_values = {}
        i = 0
        while not export_values and i < self.N_RETRIES:
            try:
                export_values = {export["Name"]: export["Value"] for export in client.list_exports().get("Exports", [])}
            except ClientError as e:
                if e.response["Error"]["Code"] == "AccessDenied":
                    logger.warning(
                        f"Access Denied for obtaining AWS Export values! ({self.account_id} - {self.region})"
                    )
                    return export_values
                elif e.response["Error"]["Code"] == "Throttling":
                    logger.warning(f"AWS Throttling: {self.stack_id} on {self.account_id} - {self.region}")
                    sleep((i + 1) * 2)
                else:
                    logger.exception(
                        f"Unhandled ClientError getting AWS Export values! ({self.account_id} - {self.region})"
                    )
            except Exception:
                logger.exception(f"Unknown exception getting AWS Export values! ({self.account_id} - {self.region})")
            i += 1
        return export_values
