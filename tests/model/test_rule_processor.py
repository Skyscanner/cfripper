from unittest.mock import Mock

import pytest

from cfripper.rule_processor import RuleProcessor
from tests.utils import get_fixture_json


@pytest.fixture()
def template():
    return get_fixture_json("rules/CloudFormationAuthenticationRule/cfn_authentication_good.json")


def test_with_mock_rule(template):
    rule = Mock()

    processor = RuleProcessor(rule)

    config = Mock()
    processor.process_cf_template(template, config)

    rule.invoke.assert_called()
