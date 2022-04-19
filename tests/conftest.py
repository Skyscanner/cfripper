import logging
from pathlib import Path

import pytest
from pycfmodel.model.resources.generic_resource import GenericResource

from cfripper.config.config import Config
from cfripper.config.filter import Filter
from cfripper.model.enums import RuleMode
from cfripper.rules import DEFAULT_RULES


@pytest.fixture(scope="session", autouse=True)
def default_session_fixture(request):
    """Logging disabled when running tests."""

    logging.disable(logging.CRITICAL)


@pytest.fixture(scope="session", autouse=True)
def disallow_allowing_typed_generic_resources():
    GenericResource.ALLOW_EXISTING_TYPES = False


@pytest.fixture
def test_files_location() -> Path:
    return Path(__file__).parent / "test_files"


@pytest.fixture()
def default_allow_all_config():
    return Config(
        rules=DEFAULT_RULES,
        aws_account_id="123456789012",
        stack_name="mockstack",
        rules_filters=[
            Filter(
                rule_mode=RuleMode.ALLOWED,
                eval={
                    "and": [
                        {"exists": {"ref": "config.stack_name"}},
                        {"eq": [{"ref": "config.stack_name"}, "mockstack"]},
                    ]
                },
                rules=set(DEFAULT_RULES.keys()),
            ),
        ],
    )


@pytest.fixture
def default_aws_region() -> str:
    return "eu-west-1"
