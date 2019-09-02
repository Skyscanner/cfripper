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
REGEX_CROSS_ACCOUNT_ROOT = r"arn:aws:iam::\d*:root"

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
REGEX_FULL_WILDCARD_PRINCIPAL = r"^((\w*:){0,1}\*|arn:aws:iam::\*:.*)$"

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
REGEX_WILDCARD_POLICY_ACTION = r"^(\w*:)(\w*)\*(\w*)$"
