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


from mock import patch
from cfripper.config.config import Config


class TestConfig:
    def test_init_with_no_params(self):
        config = Config()
        assert config.RULES is None

    def test_init_with_nonexistent_params(self):
        default_rules = [
            'IAMRolesOverprivilegedRule',
            'SecurityGroupOpenToWorldRule'
        ]
        config = Config('MISSING', 'MISSING', 'MISSING', rules=default_rules)

        assert set(config.RULES) == set(default_rules)

    def test_with_exemption(self):
        whitelist = {
            'test_project': {
                'test_service': {
                    'test_stack': ['IAMRolesOverprivilegedRule'],
                }
            }
        }

        with patch('cfripper.config.whitelist.whitelist', new=whitelist):
            from cfripper.config.config import Config
            default_rules = [
                'IAMRolesOverprivilegedRule',
                'SecurityGroupOpenToWorldRule'
            ]
            cfg = Config('test_project', 'test_service', 'test_stack', rules=default_rules)

            assert set(cfg.RULES) != set(default_rules)

    def test_with_non_existing_exemption(self):
        whitelist = {
            'test_project': {
                'test_service': {
                    'test_stack': ['MISSING'],
                }
            }
        }

        with patch('cfripper.config.whitelist.whitelist', new=whitelist):
            from cfripper.config.config import Config
            default_rules = [
                'IAMRolesOverprivilegedRule',
                'SecurityGroupOpenToWorldRule'
            ]
            cfg = Config('test_project', 'test_service', 'test_stack', rules=default_rules)

            assert set(cfg.RULES) == set(default_rules)
