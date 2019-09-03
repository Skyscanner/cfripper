import pytest
import re

from cfripper.config.regex import REGEX_CROSS_ACCOUNT_ROOT, REGEX_FULL_WILDCARD_PRINCIPAL, REGEX_WILDCARD_POLICY_ACTION


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
    ],
)
def test_regex_cross_account_root(regex, data, valid):
    assert (re.match(regex, data) is not None) == valid
