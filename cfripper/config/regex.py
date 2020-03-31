import re

"""
Check for Principals where root is being used.
Valid:
- arn:aws:iam::437628376:root
- arn:aws:iam::344345345:root
- arn:aws:iam:::root
Invalid:
- arn:aws:iam::437628376:not-root
- potato
"""
REGEX_CROSS_ACCOUNT_ROOT = re.compile(r"arn:aws:iam::\d*:root")

"""
Check for use of wildcard in two bad cases: full wildcard, or wildcard in account ID.
Valid:
- *
- arn:aws:iam::*:12345
Invalid:
- arn:aws:iam::444455556666:root
- potato
- arn:aws:iam::12345:*
"""
REGEX_FULL_WILDCARD_PRINCIPAL = re.compile(r"^((\w*:){0,1}\*|arn:aws:iam::\*:.*)$")

"""
Check for use of wildcard, when applied to the specific elements of an Action.
For example, sts:AssumeRole* or sts:*. This regex is not checking for use of `*` on its own.
Valid:
- sts:AssumeRole*
- sts:*
Invalid:
- sts:AssumeRole
- sts:AssumeRole-Thing-This
- *
"""
REGEX_WILDCARD_POLICY_ACTION = re.compile(r"^(\w*:)(\w*)\*(\w*)$")

"""
Check for Principals where root is being used.
Valid:
- *
- abc*def
- abcdef*
- *abcdef
Invalid:
- arn:aws:iam::437628376:not-root
- potato
"""
REGEX_CONTAINS_STAR = re.compile(r"^.*[*].*$")


"""
Check for root wildcard
Valid:
- *
Invalid:
- abc*def
- abcdef*
- *abcdef
- arn:aws:iam::437628376:not-root
- potato
"""
REGEX_IS_STAR = re.compile(r"^\*$")


"""
Check for arns
It has 4 groups. The first one for service name, the second one for region, the third, for account id, the last one
for resource id
Valid:
- arn:aws:iam::437628376:not-root
- arn:aws:iam::437628376:root
- arn:aws:s3:::my_corporate_bucket
Invalid:
- potato
"""
REGEX_ARN = re.compile(r"^arn:aws:(\w+):(\w*):(\d*):(.+)$")

"""
Check for iam arns
It has 2 groups. The first one for account id, the last one for resource id
Valid:
- arn:aws:iam::437628376:not-root
Invalid:
- arn:aws:s3:::my_corporate_bucket
- potato
"""
REGEX_IAM_ARN = re.compile(r"^arn:aws:iam::(\d*):(.*)$")


"""
Check for sts arns
It has 2 groups. The first one for account id, the last one for resource id
Valid:
- arn:aws:sts::437628376:not-root
Invalid:
- arn:aws:s3:::my_corporate_bucket
- potato
"""
REGEX_STS_ARN = re.compile(r"^arn:aws:sts::(\d*):(.*)$")


"""
Check for wildcards after colons
Valid:
- *
- arn:aws:iam::437628376:*
- sns:*
Invalid:
- arn:aws:s3:::my_corporate_bucket
- arn:aws:s3:::my_corporate_bucket*
- arn:aws:s3:::*my_corporate_bucket
- potato
- sns:Get*
"""
REGEX_HAS_STAR_OR_STAR_AFTER_COLON = re.compile(r"^(\w*:)*\*$")
