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
import traceback
from unittest.mock import ANY, Mock, patch

import pycfmodel
import pytest
from moto import mock_s3

from cfripper.config.config import Config
from cfripper.main import handler
from cfripper.model.result import Result
from cfripper.model.utils import convert_json_or_yaml_to_dict
from cfripper.rule_processor import RuleProcessor
from cfripper.rules import DEFAULT_RULES
from tests.utils import get_templates


def test_wrong_event_type():
    event = {}
    with pytest.raises(ValueError):
        handler(event, None)


def test_correct_event():
    event = {"stack_template_url": "https://asdfasdfasdf/bucket/key", "stack": {"name": "blooblah"}}

    mock_created_s3_adapter_object = Mock()
    mock_created_s3_adapter_object.download_template_to_dictionary.return_value = {"Resources": {}}
    mock_boto3_adapter = Mock(return_value=mock_created_s3_adapter_object)

    mock_created_boto3_client_object = Mock()
    mock_created_boto3_client_object.get_template.return_value = {"Resources": {}}
    mock_created_boto3_client_object.compare_outputs.return_value = {}
    mock_boto3_client = Mock(return_value=mock_created_boto3_client_object)

    mock_created_rule_processor_object = Mock()
    mock_rule_processor = Mock(return_value=mock_created_rule_processor_object)
    mock_rule_processor.remove_debug_rules.return_value = []

    with patch("cfripper.main.Boto3Client", new=mock_boto3_adapter):
        with patch("cfripper.main.RuleProcessor", new=mock_rule_processor):
            with patch("cfripper.main.Boto3Client", new=mock_boto3_client):
                from cfripper.main import handler

            handler(event, None)

    cfmodel = pycfmodel.parse({"Resources": {}}).resolve()
    mock_created_s3_adapter_object.download_template_to_dictionary.assert_called_once_with(
        "https://asdfasdfasdf/bucket/key"
    )
    mock_created_rule_processor_object.process_cf_template.assert_called_once_with(cfmodel, ANY, ANY)


@mock_s3
@pytest.mark.parametrize("cf_path", get_templates())
def test_with_templates(cf_path):
    with open(cf_path) as cf_script:
        cf_template = convert_json_or_yaml_to_dict(cf_script.read())

    config = Config(project_name=cf_path, service_name=cf_path, stack_name=cf_path, rules=DEFAULT_RULES.keys())

    # Scan result
    result = Result()

    cfmodel = pycfmodel.parse(cf_template).resolve()

    rules = [DEFAULT_RULES.get(rule)(config, result) for rule in config.rules]
    processor = RuleProcessor(*rules)
    processor.process_cf_template(cfmodel, config, result)

    # Use this to print the stack if there'IAMManagedPolicyWildcardActionRule an error
    if len(result.exceptions):
        print(cf_path)
        traceback.print_tb(result.exceptions[0].__traceback__)

    assert len(result.exceptions) == 0


def test_all_rules_valid():
    for r in DEFAULT_RULES.values():
        if r.RULE_MODE not in ["BLOCKING", "MONITOR", "DEBUG"]:
            assert False
    assert True


def test_stack_whitelist_joins_all_whitelisted_matching_stack_names():
    mock_whitelist = {
        "stackname": ["S3CrossAccountTrustRule"],
        "notstackname": ["IAMRolesOverprivilegedRule"],
        "stackname_withmorethings": ["CrossAccountTrustRule", "ManagedPolicyOnUserRule"],
    }

    config = Config(
        project_name="project_mock",
        service_name="service_mock",
        stack_name="stackname_withmorethings",
        stack_whitelist=mock_whitelist,
        rules=DEFAULT_RULES.keys(),
    )

    whitelisted_rules = config.get_whitelisted_rules()

    assert set(whitelisted_rules) == {"CrossAccountTrustRule", "ManagedPolicyOnUserRule", "S3CrossAccountTrustRule"}
