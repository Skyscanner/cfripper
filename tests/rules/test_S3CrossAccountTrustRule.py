"""
Copyright 2019 Skyscanner Ltd

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

from cfripper.config.config import Config
from cfripper.rules.S3CrossAccountTrustRule import S3CrossAccountTrustRule
from cfripper.model.result import Result
from tests.utils import get_cfmodel_from


@pytest.fixture()
def s3_bucket_cross_account():
    return get_cfmodel_from("rules/S3CrossAccountTrustRule/s3_bucket_cross_account.json").resolve()


@pytest.fixture()
def s3_bucket_cross_account_and_normal():
    return get_cfmodel_from("rules/S3CrossAccountTrustRule/s3_bucket_cross_account_and_normal.json").resolve()


def test_s3_bucket_cross_account(s3_bucket_cross_account):
    result = Result()
    rule = S3CrossAccountTrustRule(Config(aws_account_id="123456789"), result)
    rule.invoke(s3_bucket_cross_account)

    assert not result.valid
    assert len(result.failed_rules) == 1
    assert len(result.failed_monitored_rules) == 0
    assert result.failed_rules[0]["rule"] == "S3CrossAccountTrustRule"
    assert (
        result.failed_rules[0]["reason"]
        == "S3BucketPolicyAccountAccess has forbidden cross-account policy allow with arn:aws:iam::987654321:root for an S3 bucket."
    )


def test_s3_bucket_cross_account_and_normal(s3_bucket_cross_account_and_normal):
    result = Result()
    rule = S3CrossAccountTrustRule(Config(aws_account_id="123456789"), result)
    rule.invoke(s3_bucket_cross_account_and_normal)

    assert not result.valid
    assert len(result.failed_rules) == 1
    assert len(result.failed_monitored_rules) == 0
    assert result.failed_rules[0]["rule"] == "S3CrossAccountTrustRule"
    assert (
        result.failed_rules[0]["reason"]
        == "S3BucketPolicyAccountAccess has forbidden cross-account policy allow with arn:aws:iam::666555444:root for an S3 bucket."
    )
