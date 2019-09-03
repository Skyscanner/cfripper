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
Script to simulate lambda execution using local CF scripts.

The S3 download is mocked and local scripts in the simulator/test_cf_scripts are used.
Make sure to add the script info in the "scripts" dictionary below.
"""

import os
import sys
import logging
from unittest.mock import Mock, patch


logging.basicConfig(level=logging.INFO)
sys.path.append("../")
sys.path.append("../cfripper/")
from cfripper.model.utils import convert_json_or_yaml_to_dict

dir_path = os.path.dirname(os.path.realpath(__file__))

"""
{
    'script_name': 'exmaple.json',
    'service_name': 'example_service',
    'project_name': 'example_project',
}
"""
scripts = [{"script_name": "test.json", "service_name": "", "project_name": "", "stack": {"name": "TSS_12124"}}]


def test_script(script_name, service_name, project_name, stack):
    event = {
        "stack_template_url": "https://fake/bucket/key",
        "project": project_name,
        "serviceName": service_name,
        "stack": stack,
    }
    mock_created_s3_adapter_object = Mock()
    with open(f"{dir_path}/test_cf_scripts/{script_name}") as cf_script:
        mock_created_s3_adapter_object.download_template_to_dictionary.return_value = convert_json_or_yaml_to_dict(
            cf_script.read()
        )

    mock_s3_adapter = Mock(return_value=mock_created_s3_adapter_object)

    with patch("cfripper.main.S3Adapter", new=mock_s3_adapter):
        from cfripper.main import handler

        event_result = handler(event, "None")
        print(f"{script_name} -- valid: {event_result['valid']}\n {event_result['reason']}")


def test_scripts():
    for script in scripts:
        test_script(script["script_name"], script["service_name"], script["project_name"], script["stack"])


if __name__ == "__main__":
    test_scripts()
