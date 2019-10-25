import json
import os

from pathlib import Path
from typing import Dict, List

from pycfmodel import parse
from pycfmodel.model.cf_model import CFModel


FIXTURE_ROOT_PATH = Path(__file__).parent / "test_templates"


def get_templates() -> List[str]:
    for r, d, f in os.walk(FIXTURE_ROOT_PATH):
        for file_path in f:
            filename, file_extension = os.path.splitext(file_path)
            if file_extension in [".json", ".yml", ".yaml"] and filename not in [
                "wildcard_principal_rule_is_whitelisted_retrieved_correctly"
            ]:
                yield os.path.join(r, file_path)


def get_fixture_json(path: str) -> Dict:
    with Path(FIXTURE_ROOT_PATH / path).open() as f:
        response = json.load(f)
    return response


def get_cfmodel_from(path: str) -> CFModel:
    return parse(get_fixture_json(path))
