import re

"""
Check for Principals where root is being used.
Valid:
- arn:aws:iam::123456789012:root
- arn:aws:iam:::root
Invalid:
- arn:aws:iam::123456789012:not-root
- potato
"""
REGEX_CROSS_ACCOUNT_ROOT = re.compile(r"arn:aws:iam::\d*:root")

"""
Check for use of wildcard in two bad cases: full wildcard, or wildcard in account ID.
Valid:
- *
- ?*
- **
- arn:aws:iam::*:12345
Invalid:
- arn:aws:iam::123456789012:root
- potato
- arn:aws:iam::123456789012:*
"""
REGEX_FULL_WILDCARD_PRINCIPAL = re.compile(r"^((\w*:)?[*?]+|arn:aws:iam::[*?]+:.*)$")

"""
Check for use of wildcard or account-wide principals.
Valid:
- arn:aws:iam::123456789012:*
- arn:aws:iam::123456789012:service-*
- arn:aws:iam::123456789012:root
- arn:aws:iam::123456789012:*-role
- 123456789012
- 79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be
- eb2fe74dc7e8125d8f8fcae89d90e6dfdecabf896e1a69d55e949b009fd95a97
Invalid:
- *
- potato
- arn:aws:iam::123456789012:not-root
"""
REGEX_PARTIAL_WILDCARD_PRINCIPAL = re.compile(
    r"^(\d{12})|([a-fA-F0-9]{64})|(arn:aws:iam::(\d+):(.*[*?]+|[*?]+.*|root))$"
)

"""
Check for use of wildcard, when applied to the specific elements of an Action.
For example, sts:AssumeRole* or sts:*. This regex is not checking for use of `*` on its own.
Valid:
- sts:AssumeRole*
- sts:*
- sts:Assume????
- sts:??????Role
- sts:*Role*
Invalid:
- sts:AssumeRole
- sts:AssumeRole-Thing-This
- *
"""
REGEX_WILDCARD_POLICY_ACTION = re.compile(r"^(\w*:)(.*)[*?]+(.*)$")

"""
Check for Principals where a star is being used.
Valid:
- *
- abc*def
- abcdef*
- *abcdef
Invalid:
- arn:aws:iam::123456789012:not-root
- potato
"""
REGEX_CONTAINS_STAR = re.compile(r"^.*[*].*$")

"""
Check for an str where a wildcard (* or ?) is being used.
Valid:
- *
- ?
- abc*def
- abc?def
- abcdef*
- abcdef?
- *abcdef
- ?abcdef
Invalid:
- arn:aws:iam::123456789012:not-root
- potato
"""
REGEX_CONTAINS_WILDCARD = re.compile(r"^.*[*?].*$")


"""
Check for root wildcard
Valid:
- *
Invalid:
- abc*def
- abcdef*
- *abcdef
- arn:aws:iam::123456789012:not-root
- potato
"""
REGEX_IS_STAR = re.compile(r"^\*$")


"""
Check for arns
It has 4 groups. The first one for service name, the second one for region, the third, for account id, the last one
for resource id
Valid:
- arn:aws:iam::123456789012:not-root
- arn:aws:iam::123456789012:root
- arn:aws:s3:::my_corporate_bucket
Invalid:
- potato
"""
REGEX_ARN = re.compile(r"^arn:aws:(\w+):(\w*):(\d*):(.+)$")


"""
Check for arns that allow the full aws service range in a particular service
Valid:
- arn:aws:s3:::*
- arn:aws:iam:*:*:*
- arn:aws:*:::*
Invalid:
- potato
- arn:aws:s3:::my_corporate_bucket
- arn:aws:iam::123456789012:root
"""
REGEX_WILDCARD_ARN = re.compile(r"^arn:aws:([*\w]+):([*?]*):([*?]*):([*?]+)$")


"""
Check for iam arns
It has 2 groups. The first one for account id, the last one for resource id
Valid:
- arn:aws:iam::123456789012:not-root
Invalid:
- arn:aws:s3:::my_corporate_bucket
- potato
"""
REGEX_IAM_ARN = re.compile(r"^arn:aws:iam::(\d+):(.*)$")


"""
Check for sts arns
It has 2 groups. The first one for account id, the last one for resource id
Valid:
- arn:aws:sts::123456789012:not-root
Invalid:
- arn:aws:s3:::my_corporate_bucket
- potato
"""
REGEX_STS_ARN = re.compile(r"^arn:aws:sts::(\d+):(.*)$")


"""
Check for a wildcard star or wildcards immediately after the last colon
Valid:
- *
- arn:aws:iam::123456789012:*
- arn:aws:iam::123456789012:??????
- arn:aws:iam::123456789012:?*
- sns:*
Invalid:
- arn:aws:s3:::my_corporate_bucket
- arn:aws:s3:::my_corporate_bucket*
- arn:aws:s3:::*my_corporate_bucket
- potato
- sns:Get*
"""
REGEX_HAS_STAR_OR_STAR_AFTER_COLON = re.compile(r"^(\w*:)*[*?]+$")


"""
Check that stack name only consists of alphanumerical characters and hyphens.
Valid:
- abcdefg
- ABCDEFG
- abcdEFG
- aBc-DeFG
- a1b2c3
Invalid:
- abc_defg
- AB:cdefg
- !@£$$%aA
"""
REGEX_ALPHANUMERICAL_OR_HYPHEN = re.compile(r"^[A-Za-z0-9\-]+$")
