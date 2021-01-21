import logging
from pathlib import Path

import pytest


@pytest.fixture(scope="session", autouse=True)
def default_session_fixture(request):
    """Logging disabled when running tests."""

    logging.disable(logging.CRITICAL)


@pytest.fixture
def test_files_location() -> Path:
    return Path(__file__).parent / "test_files"
