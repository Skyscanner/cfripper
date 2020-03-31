"""
Script to simulate lambda execution using local CF scripts.

The S3 download is mocked and local scripts in the simulator/test_cf_scripts are used.
Make sure to add the script info in the "scripts" dictionary below.
"""
import logging
import os
import sys
from unittest.mock import Mock, patch

from cfripper.model.utils import convert_json_or_yaml_to_dict

logging.basicConfig(level=logging.INFO)
sys.path.append("../")
sys.path.append("../cfripper/")

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
    mock_boto3_client_object = Mock()
    with open(f"{dir_path}/test_cf_scripts/{script_name}") as cf_script:
        mock_boto3_client_object.download_template_to_dictionary.return_value = convert_json_or_yaml_to_dict(
            cf_script.read()
        )

    mock_boto3_client = Mock(return_value=mock_boto3_client_object)

    with patch("cfripper.main.Boto3Client", new=mock_boto3_client):
        from cfripper.main import handler

        event_result = handler(event, "None")
        print(f"{script_name} -- valid: {event_result['valid']}\n {event_result['reason']}")


def test_scripts():
    for script in scripts:
        test_script(script["script_name"], script["service_name"], script["project_name"], script["stack"])


if __name__ == "__main__":
    test_scripts()
