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
from pathlib import Path

import pytest

from cfripper.rules.CrossAccountTrustRule import CrossAccountTrustRule
from cfripper.config.config import Config
from cfripper.model.result import Result

from tests.utils import get_cfmodel_from


@pytest.fixture()
def template():
    return get_cfmodel_from("rules/CrossAccountTrustRule/template.json").resolve()


def test_with_test_template_wildcards(template):
    result = Result()
    rule = CrossAccountTrustRule(Config(aws_account_id="123456789"), result)
    rule.invoke(template)

    assert not result.valid
    assert len(result.failed_rules) == 2
    assert len(result.failed_monitored_rules) == 0
    assert result.failed_rules[0]["rule"] == "CrossAccountTrustRule"
    assert (
        result.failed_rules[0]["reason"]
        == "RootRole has forbidden cross-account trust relationship with arn:aws:iam::123456789:root"
    )
    assert result.failed_rules[0]["rule"] == "CrossAccountTrustRule"
    assert (
        result.failed_rules[1]["reason"]
        == "RootRole has forbidden cross-account trust relationship with arn:aws:iam::999999999:role/someuser@bla.com"
    )
