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
from typing import Dict

import pytest

from cfripper.model.utils import convert_json_or_yaml_to_dict, extract_bucket_name_and_path_from_url, replace_tabs


@pytest.mark.parametrize(
    "template_url, bucket, path",
    [
        ("https://cf-templates.s3.amazonaws.com/path/to/template.yml", "cf-templates", "path/to/template.yml"),
        (
            "https://cf-templates.s3-eu-central-1.amazonaws.com/path/to/template.yml",
            "cf-templates",
            "path/to/template.yml",
        ),
        ("https://s3.amazonaws.com/cf-templates/path/to/template.yml", "cf-templates", "path/to/template.yml"),
        (
            "https://s3.eu-central-1.amazonaws.com/cf-templates/path/to/template.yml",
            "cf-templates",
            "path/to/template.yml",
        ),
        (
            "https://s3-eu-central-1.amazonaws.com/cf-templates/path/to/template.yml",
            "cf-templates",
            "path/to/template.yml",
        ),
    ],
)
def test_stack_delete(template_url, bucket, path):
    assert extract_bucket_name_and_path_from_url(template_url) == (bucket, path)


@pytest.mark.parametrize(
    "input, expected_output",
    [
        ("", ""),
        (" ", " "),
        ("\r\n", "\r\n"),
        ("\t", "  "),
        ("a\t", "a  "),
        ("\ta", "  a"),
        ("\ta\t", "  a  "),
        ("a\ta", "a  a"),
    ],
)
def test_replace_tabs(input, expected_output):
    assert replace_tabs(input) == expected_output


@pytest.mark.parametrize(
    "input, expected_output",
    [
        ('{"A": "a"}', {"A": "a"}),
        ("A: a", {"A": "a"}),
        ("\tA: a", {"A": "a"}),
        ("\tA:\t  a\n  B: b", {"A": "a", "B": "b"}),
    ],
)
def test_convert_json_or_yaml_to_dict(input, expected_output):
    assert convert_json_or_yaml_to_dict(input) == expected_output


def test_convert_json_or_yaml_to_dict_yaml_with_tabs():
    cf_path = "tests/test_templates/others/yaml_with_tabs.yml"
    with open(cf_path) as cf_script:
        assert isinstance(convert_json_or_yaml_to_dict(cf_script.read()), Dict)
