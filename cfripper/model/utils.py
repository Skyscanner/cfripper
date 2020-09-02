import json
import logging
import re
from contextlib import suppress
from functools import lru_cache
from typing import Optional
from urllib.parse import unquote

import boto3
import yaml
from cfn_flip import to_json
from pycfmodel.model.resources.properties.policy import Policy

from cfripper.config.regex import REGEX_ARN, REGEX_IAM_ARN, REGEX_STS_ARN

logger = logging.getLogger(__file__)


class InvalidURLException(Exception):
    pass


def extract_bucket_name_and_path_from_url(url):
    # Remove query string
    url = unquote(url).split("?")[0]

    bucket_name = None
    path = None

    # https://bucket.s3.amazonaws.com/path1/path2
    match = re.search(r"^https://([^.]+)\.s3\.amazonaws\.com(.*?)$", url)
    if match:
        bucket_name, path = match.group(1), match.group(2)[1:]  # Trim start /

    # https://bucket.s3.aws-region.amazonaws.com/path1/path2
    match = re.search(r"^https://([^.]+)\.s3\.[^\.]+\.amazonaws\.com(.*?)$", url)
    if match:
        bucket_name, path = match.group(1), match.group(2)[1:]  # Trim start /

    # https://bucket.s3-aws-region.amazonaws.com/path1/path2
    match = re.search(r"^https://([^.]+)\.s3-[^\.]+\.amazonaws\.com(.*?)$", url)
    if match:
        bucket_name, path = match.group(1), match.group(2)[1:]  # Trim start /

    # https://s3.amazonaws.com/bucket/path1/path2
    match = re.search(r"^https://s3\.amazonaws\.com/([^\/]+)(.*?)$", url)
    if match:
        bucket_name, path = match.group(1), match.group(2)[1:]  # Trim start /

    # https://s3.aws-region.amazonaws.com/bucket/path1/path2
    match = re.search(r"^https://s3\.[^.]+\.amazonaws\.com/([^\/]+)(.*?)$", url)
    if match:
        bucket_name, path = match.group(1), match.group(2)[1:]  # Trim start /

    # https://s3-aws-region.amazonaws.com/bucket/path1/path2
    match = re.search(r"^https://s3-[^.]+\.amazonaws\.com/([^\/]+)(.*?)$", url)
    if match:
        bucket_name, path = match.group(1), match.group(2)[1:]  # Trim start /

    if bucket_name is None and path is None:
        raise InvalidURLException(f"Couldn't extract bucket name and path from url: {url}")

    logger.info(f"extract_bucket_name_and_path_from_url. returning for {bucket_name} and {path} for {url}")

    return bucket_name, path


def convert_json_or_yaml_to_dict(file_content):
    with suppress(ValueError):
        return json.loads(file_content)

    try:
        # Convert file_content (assuming that is YAML) to JSON if possible
        file_content = to_json(file_content)
        return json.loads(file_content)
    except yaml.YAMLError:
        logger.exception("Could not convert YAML to JSON template")
    except ValueError:
        logger.exception("Could not parse JSON template")

    return None


@lru_cache(maxsize=None)
def get_managed_policy(managed_policy_arn):
    iam_client = boto3.client("iam")
    managed_policy = iam_client.get_policy(PolicyArn=managed_policy_arn)
    version_id = managed_policy.get("Policy", {}).get("DefaultVersionId")
    if version_id:
        policy_version = iam_client.get_policy_version(PolicyArn=managed_policy_arn, VersionId=version_id)
        return Policy(
            **{
                "PolicyDocument": policy_version["PolicyVersion"]["Document"],
                "PolicyName": f"AutoTransformedManagedPolicy{version_id}",
            }
        )
    return None


def get_aws_service_from_arn(arn: str) -> Optional[str]:
    match = REGEX_ARN.match(arn)
    if match:
        return match.group(1)


def get_account_id_from_arn(arn: str) -> Optional[str]:
    match = REGEX_ARN.match(arn)
    if match:
        return match.group(3)


def get_account_id_from_iam_arn(arn: str) -> Optional[str]:
    match = REGEX_IAM_ARN.match(arn)
    if match:
        return match.group(1)


def get_account_id_from_sts_arn(arn: str) -> Optional[str]:
    match = REGEX_STS_ARN.match(arn)
    if match:
        return match.group(1)


def get_account_id_from_principal(principal: str) -> Optional[str]:
    if principal.isnumeric():
        return principal

    aws_service = get_aws_service_from_arn(principal)
    if aws_service not in ["iam", "sts"]:
        return None

    if aws_service == "iam":
        return get_account_id_from_iam_arn(principal)
    elif aws_service == "sts":
        return get_account_id_from_sts_arn(principal)
