"""
Copyright 2018-2019 Skyscanner Ltd

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

from cfripper.config.regex import (
    REGEX_ARN,
    REGEX_CONTAINS_STAR,
    REGEX_CROSS_ACCOUNT_ROOT,
    REGEX_FULL_WILDCARD_PRINCIPAL,
    REGEX_HAS_STAR_OR_STAR_AFTER_COLON,
    REGEX_IAM_ARN,
    REGEX_IS_STAR,
    REGEX_STS_ARN,
    REGEX_WILDCARD_POLICY_ACTION,
)


@pytest.mark.parametrize(
    "regex, data, valid",
    [
        (REGEX_CROSS_ACCOUNT_ROOT, "arn:aws:iam::437628376:root", True),
        (REGEX_CROSS_ACCOUNT_ROOT, "arn:aws:iam::344345345:root", True),
        (REGEX_CROSS_ACCOUNT_ROOT, "arn:aws:iam:::root", True),
        (REGEX_CROSS_ACCOUNT_ROOT, "arn:aws:iam::437628376:not-root", False),
        (REGEX_CROSS_ACCOUNT_ROOT, "potato", False),
        (REGEX_FULL_WILDCARD_PRINCIPAL, "*", True),
        (REGEX_FULL_WILDCARD_PRINCIPAL, "arn:aws:iam::*:12345", True),
        (REGEX_FULL_WILDCARD_PRINCIPAL, "arn:aws:iam::444455556666:root", False),
        (REGEX_FULL_WILDCARD_PRINCIPAL, "potato", False),
        (REGEX_FULL_WILDCARD_PRINCIPAL, "arn:aws:iam::12345:*", False),
        (REGEX_WILDCARD_POLICY_ACTION, "sts:AssumeRole*", True),
        (REGEX_WILDCARD_POLICY_ACTION, "sts:*", True),
        (REGEX_WILDCARD_POLICY_ACTION, "sts:AssumeRole", False),
        (REGEX_WILDCARD_POLICY_ACTION, "sts:AssumeRole-Thing-This", False),
        (REGEX_WILDCARD_POLICY_ACTION, "*", False),
        (REGEX_CONTAINS_STAR, "*", True),
        (REGEX_CONTAINS_STAR, "abc*def", True),
        (REGEX_CONTAINS_STAR, "abcdef*", True),
        (REGEX_CONTAINS_STAR, "*abcdef", True),
        (REGEX_CONTAINS_STAR, "arn:aws:iam::437628376:not-root", False),
        (REGEX_CONTAINS_STAR, "potato", False),
        (REGEX_IS_STAR, "*", True),
        (REGEX_IS_STAR, "abc*def", False),
        (REGEX_IS_STAR, "abcdef*", False),
        (REGEX_IS_STAR, "*abcdef", False),
        (REGEX_IS_STAR, "arn:aws:iam::437628376:not-root", False),
        (REGEX_IS_STAR, "potato", False),
        (REGEX_ARN, "arn:aws:iam::437628376:not-root", True),
        (REGEX_ARN, "arn:aws:iam::437628376:root", True),
        (REGEX_ARN, "arn:aws:s3:::my_corporate_bucket", True),
        (REGEX_ARN, "potato", False),
        (REGEX_IAM_ARN, "arn:aws:iam::437628376:not-root", True),
        (REGEX_IAM_ARN, "arn:aws:iam::437628376:root", True),
        (REGEX_IAM_ARN, "arn:aws:s3:::my_corporate_bucket", False),
        (REGEX_IAM_ARN, "potato", False),
        (REGEX_STS_ARN, "arn:aws:sts::437628376:not-root", True),
        (REGEX_STS_ARN, "arn:aws:sts::437628376:root", True),
        (REGEX_STS_ARN, "arn:aws:s3:::my_corporate_bucket", False),
        (REGEX_STS_ARN, "potato", False),
        (REGEX_HAS_STAR_OR_STAR_AFTER_COLON, "arn:aws:iam::437628376:*", True),
        (REGEX_HAS_STAR_OR_STAR_AFTER_COLON, "*", True),
        (REGEX_HAS_STAR_OR_STAR_AFTER_COLON, "sns:*", True),
        (REGEX_HAS_STAR_OR_STAR_AFTER_COLON, "arn:aws:iam::437628376:root", False),
        (REGEX_HAS_STAR_OR_STAR_AFTER_COLON, "arn:aws:s3:::my_corporate_bucket*", False),
        (REGEX_HAS_STAR_OR_STAR_AFTER_COLON, "arn:aws:s3:::*my_corporate_bucket", False),
        (REGEX_HAS_STAR_OR_STAR_AFTER_COLON, "potato", False),
        (REGEX_HAS_STAR_OR_STAR_AFTER_COLON, "sns:Get*", False),
    ],
)
def test_regex_cross_account_root(regex, data, valid):
    assert (regex.match(data) is not None) == valid, f"{data} failed"
