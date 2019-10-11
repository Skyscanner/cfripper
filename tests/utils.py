import json
import os

from pathlib import Path
from typing import Dict, List

from pycfmodel import parse
from pycfmodel.model.cf_model import CFModel


FIXTURE_ROOT_PATH = Path(__file__).parent / "test_templates"


def get_templates() -> List[str]:
    for r, d, f in os.walk(FIXTURE_ROOT_PATH):
        for file in f:
            yield os.path.join(r, file)


def get_fixture_json(path: str) -> Dict:
    with Path(FIXTURE_ROOT_PATH / path).open() as f:
        response = json.load(f)
    return response


def get_cfmodel_from(path: str) -> CFModel:
    return parse(get_fixture_json(path))
