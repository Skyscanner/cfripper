from typing import Dict, Optional

import pytest
from pycfmodel.model.cf_model import CFModel

from cfripper.config.config import Config
from cfripper.model.result import Result
from cfripper.rules.base_rules import PrincipalCheckingRule


class FakePrincipalCheckingRule(PrincipalCheckingRule):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        return Result()


@pytest.mark.parametrize(
    "rule, params, expected_output",
    [
        (
            FakePrincipalCheckingRule(config=Config(aws_service_accounts=None)),
            None,
            {
                "009996457667",
                "027434742980",
                "033677994240",
                "037604701340",
                "048591011584",
                "054676820928",
                "076674570225",
                "114774131450",
                "127311923021",
                "156460612806",
                "190560391635",
                "383597477331",
                "40fa568277ad703bd160f66ae4f83fc9dfdfd06c2f1b5060ca22442ac3ef8be6",
                "507241528517",
                "540804c33a284a299d2547575ce1010f2312ef3da9b3a053c8bc45bf233e4353",
                "582318560864",
                "600734575887",
                "638102146993",
                "652711504416",
                "718504428378",
                "754344448648",
                "783225319266",
                "797873946194",
                "897822967062",
                "985666609251",
                "b14d6a125bdf69854ed8ef2e71d8a20b7c490f252229b806e514966e490b8d83",
            },
        ),
        (
            FakePrincipalCheckingRule(config=Config(aws_service_accounts=None)),
            ["elb_logs_account_ids", "elasticache_backup_canonical_ids"],
            {
                "009996457667",
                "027434742980",
                "033677994240",
                "037604701340",
                "048591011584",
                "054676820928",
                "076674570225",
                "114774131450",
                "127311923021",
                "156460612806",
                "190560391635",
                "383597477331",
                "40fa568277ad703bd160f66ae4f83fc9dfdfd06c2f1b5060ca22442ac3ef8be6",
                "507241528517",
                "540804c33a284a299d2547575ce1010f2312ef3da9b3a053c8bc45bf233e4353",
                "582318560864",
                "600734575887",
                "638102146993",
                "652711504416",
                "718504428378",
                "754344448648",
                "783225319266",
                "797873946194",
                "897822967062",
                "985666609251",
                "b14d6a125bdf69854ed8ef2e71d8a20b7c490f252229b806e514966e490b8d83",
            },
        ),
        (
            FakePrincipalCheckingRule(config=Config(aws_service_accounts=None)),
            ["elasticache_backup_canonical_ids"],
            {
                "40fa568277ad703bd160f66ae4f83fc9dfdfd06c2f1b5060ca22442ac3ef8be6",
                "540804c33a284a299d2547575ce1010f2312ef3da9b3a053c8bc45bf233e4353",
                "b14d6a125bdf69854ed8ef2e71d8a20b7c490f252229b806e514966e490b8d83",
            },
        ),
        (FakePrincipalCheckingRule(config=Config(aws_service_accounts={"A": ["a", "b", "c"]})), None, {"a", "b", "c"},),
        (
            FakePrincipalCheckingRule(config=Config(aws_service_accounts={"A": ["a", "b", "c"], "B": ["d", "e", "f"]})),
            None,
            {"a", "b", "c", "d", "e", "f"},
        ),
        (
            FakePrincipalCheckingRule(config=Config(aws_service_accounts={"A": ["a", "b", "c"], "B": ["d", "a", "b"]})),
            None,
            {"a", "b", "c", "d"},
        ),
        (
            FakePrincipalCheckingRule(config=Config(aws_service_accounts={"A": ["a", "b", "c"]})),
            ["A"],
            {"a", "b", "c"},
        ),
        (
            FakePrincipalCheckingRule(config=Config(aws_service_accounts={"A": ["a", "b", "c"], "B": ["d", "e", "f"]})),
            ["A", "B"],
            {"a", "b", "c", "d", "e", "f"},
        ),
        (
            FakePrincipalCheckingRule(config=Config(aws_service_accounts={"A": ["a", "b", "c"], "B": ["d", "a", "b"]})),
            ["A", "B"],
            {"a", "b", "c", "d"},
        ),
    ],
)
def test_get_whitelist_from_config(rule, params, expected_output):
    assert rule._get_whitelist_from_config(params) == expected_output
