import logging

import pytest


@pytest.fixture(scope="session", autouse=True)
def default_session_fixture(request):
    """Logging disabled when running tests."""

    logging.disable(logging.CRITICAL)
