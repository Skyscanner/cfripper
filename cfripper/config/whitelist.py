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

"""
A list of projects that are allowed to skip specific checks.

The format:

whitelist = {
    "stack_name_1": [
        "rule_name_1",
        "rule_name_2",
    ],
    "stack_name_2": [
        "rule_name_2",
        "rule_name_3",
    ]
}

"""
stack_whitelist = {}

"""
A list of resources that are allowed to use wildcard principals, grouped by stack name

The format:

wildcard_principal_resource_whitelist = {
    "stack_name1": [
        "RESOURCE_NAME_1",
        "RESOURCE_NAME_2",
    ],
    "stack_name2": [
        "RESOURCE_NAME_3",
        "RESOURCE_NAME_4",
    ]
}

"""

wildcard_principal_resource_whitelist = {}

"""
A whitelist for all rules that can whitelist resources for certain stacks
stack names and resource names accept regular expressions

rule_to_resource_whitelist = {
    "rule_name_1": {
        "stack_name_1": {
            "resource_name_1",
        },
        "stack_name_2": {
            "resource_name_2",
            "resource_name_3",
        },
    },
    "rule_name_2": {
        "stack_name_1": {
            "resource_name_4",
        },
    },
}


"""
rule_to_resource_whitelist = {}

"""
A whitelist for all rules that can whitelist actions for certain stacks
stack names and actions accept regular expressions

rule_to_action_whitelist = {
    "rule_name_3": {
        "stack_name_1": {
            "aws_action:one",
        },
        "stack_name_2": {
            "raws_action:one",
            "aws_action:one",
        },
    },
    "rule_name_4": {
        "stack_name_1": {
            "aws_action:*",
        },
    },
}


"""

rule_to_action_whitelist = {}
