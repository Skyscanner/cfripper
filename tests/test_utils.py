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


from cfripper.model.utils import extract_bucket_name_and_path_from_url
import pytest


class TestUtils:
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
    def test_stack_delete(self, template_url, bucket, path):
        assert extract_bucket_name_and_path_from_url(template_url) == (bucket, path)
