import json
from pathlib import Path
from pycfmodel import parse


def get_fixture_json(path: str):
    with Path(path).open() as f:
        response = json.load(f)
    return response


def get_cfmodel_from(path: str):
    return parse(get_fixture_json(path))
