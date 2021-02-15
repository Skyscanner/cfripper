import logging
from pathlib import Path

import pytest

from cfripper.config.config import Config
from cfripper.config.filter import Filter
from cfripper.config.rule_config import RuleConfig
from cfripper.model.enums import RuleMode
from cfripper.rules import DEFAULT_RULES


@pytest.fixture(scope="session", autouse=True)
def default_session_fixture(request):
    """Logging disabled when running tests."""

    logging.disable(logging.CRITICAL)


@pytest.fixture
def test_files_location() -> Path:
    return Path(__file__).parent / "test_files"


@pytest.fixture()
def default_allow_all_config():
    return Config(
        rules=DEFAULT_RULES,
        aws_account_id="123456789",
        stack_name="mockstack",
        rules_config={
            rule: RuleConfig(
                filters=[
                    Filter(
                        rule_mode=RuleMode.WHITELISTED,
                        eval={
                            "and": [
                                {"exists": {"ref": "config.stack_name"}},
                                {"eq": [{"ref": "config.stack_name"}, "mockstack"]},
                            ]
                        },
                    ),
                ]
            )
            for rule in DEFAULT_RULES
        },
    )
