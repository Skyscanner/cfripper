import json
import os
from pathlib import Path
from typing import Dict, List

from pycfmodel import parse
from pycfmodel.model.cf_model import CFModel

from cfripper.model.result import Failure
from cfripper.model.utils import convert_json_or_yaml_to_dict

FIXTURE_ROOT_PATH = Path(__file__).parent / "test_templates"


def get_templates() -> List[str]:
    for r, d, f in os.walk(FIXTURE_ROOT_PATH):
        for file_path in f:
            filename, file_extension = os.path.splitext(file_path)
            if file_extension in [".json", ".yml", ".yaml"] and filename not in [
                "wildcard_principal_rule_is_allowed_retrieved_correctly"
            ]:
                yield os.path.join(r, file_path)


def get_fixture_json(path: str) -> Dict:
    with Path(FIXTURE_ROOT_PATH / path).open() as f:
        response = json.load(f)
    return response


def get_cfmodel_from(path: str) -> CFModel:
    with Path(FIXTURE_ROOT_PATH / path).open() as f:
        content = f.read()
    return parse(convert_json_or_yaml_to_dict(content))


def compare_lists_of_failures(list_1: List[Failure], list_2: List[Failure]) -> bool:
    return len(list_1) == len(list_2) and sorted(list_1, key=lambda item: item.reason, reverse=True) == sorted(
        list_2, key=lambda item: item.reason, reverse=True
    )
