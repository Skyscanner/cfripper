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


import traceback
import pytest
from unittest.mock import Mock, patch
from unittest.mock import ANY
import glob
import os
from cfripper.s3_adapter import S3Adapter
from cfripper.model.result import Result
from cfripper.rules import ALL_RULES
from cfripper.config.config import Config
from cfripper.model.rule_processor import RuleProcessor


class TestMainHandler:
    def test_wrong_event_type(self):
        event = {}

        from cfripper.main import handler

        with pytest.raises(ValueError):
            handler(event, None)

    def test_correct_event(self):
        event = {
            'stack_template_url': 'https://asdfasdfasdf/bucket/key'
        }

        mock_created_s3_adapter_object = Mock()
        mock_created_s3_adapter_object.download_template_to_dictionary.return_value = {
            'Resources': {}
        }
        mock_s3_adapter = Mock(return_value=mock_created_s3_adapter_object)

        mock_created_rule_processor_object = Mock()
        mock_rule_processor = Mock(return_value=mock_created_rule_processor_object)

        with patch('cfripper.main.S3Adapter', new=mock_s3_adapter):
            with patch('cfripper.main.RuleProcessor', new=mock_rule_processor):
                from cfripper.main import handler

                handler(event, None)

        mock_created_s3_adapter_object.download_template_to_dictionary.assert_called_once_with('https://asdfasdfasdf/bucket/key')
        mock_created_rule_processor_object.process_cf_template.assert_called_once_with(
            mock_created_s3_adapter_object.download_template_to_dictionary.return_value,
            ANY,
            ANY,
        )

    def test_output_contract(self):
        """
        Test that the output complies to the established protocol
        that is used by the IaC pipeline and cf-name-check.

        Output should look like:
            {
                "valid": "true", #  NOTE: this is a string and NOT a boolean
                "reason": ""
                "failed_rules": [] #  Optional
            }
        """
        event = {
            'stack_template_url': 'https://fake/bucket/key',
        }

        mock_created_s3_adapter_object = Mock()
        mock_created_s3_adapter_object.download_template_to_dictionary.return_value = {
            'Resources': {
                "sg": {
                    "Type": "AWS::EC2::SecurityGroup",
                    "Properties": {
                        "GroupDescription": "some_group_desc",
                        "SecurityGroupIngress": {
                            "CidrIp": "10.1.2.3/32",
                            "FromPort": 34,
                            "ToPort": 36,
                            "IpProtocol": "tcp"
                        },
                        "VpcId": "vpc-9f8e9dfa",
                    }
                }
            }
        }
        mock_s3_adapter = Mock(return_value=mock_created_s3_adapter_object)
        with patch('cfripper.main.S3Adapter', new=mock_s3_adapter):
            from cfripper.main import handler
            event_result = handler(event, None)

        assert event_result['valid'] == 'true'
        assert isinstance(event_result['reason'], str)
        assert isinstance(event_result.get('failed_rules'), list)

    def test_with_templates(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        test_templates = glob.glob('{}/test_templates/*.*'.format(dir_path))
        for template in test_templates:
            cf_script = open(template)
            cf_template = S3Adapter().convert_json_or_yaml_to_dict(cf_script.read())

            config = Config(
                project_name=template,
                service_name=template,
                stack_name=template,
                rules=ALL_RULES.keys(),
            )

            # Scan result
            result = Result()

            rules = [ALL_RULES.get(rule)(config, result) for rule in config.RULES]
            processor = RuleProcessor(*rules)

            processor.process_cf_template(cf_template, config, result)
            # Use this to print the stack if there's an error
            if len(result.exceptions):
                print(template)
                traceback.print_tb(result.exceptions[0].__traceback__)

            no_resource_templates = [
                'vulgar_bad_syntax.yml',
                'rubbish.json',
            ]
            if template.split('/')[-1] in no_resource_templates:
                assert len(result.exceptions) == 1
            else:
                assert len(result.exceptions) == 0

