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
import re

"""
A list of projects that are allowed to skip specific checks.

The format:

whitelist = {
    "stack_name1": [
        "RULE2",
        "RULE3",
    ],
    "stack_name2": [
        "RULE2",
        "RULE3",
    ]
}

"""
whitelist = {}


def get_stack_exemption_list(stack_name):
    for k, v in whitelist.items():
        if re.match(k, stack_name):
            return v

    return []
