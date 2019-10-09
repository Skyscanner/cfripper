import json
from pathlib import Path
from pycfmodel import parse


FIXTURE_ROOT_PATH = Path(__file__).parent / "test_templates"


def get_fixture_json(path: str):
    with Path(FIXTURE_ROOT_PATH / path).open() as f:
        response = json.load(f)
    return response


def get_cfmodel_from(path: str):
    return parse(get_fixture_json(path))
