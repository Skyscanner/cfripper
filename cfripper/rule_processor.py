import logging
from typing import Dict, List, Optional

from pycfmodel.model.cf_model import CFModel

from cfripper.config.config import Config
from cfripper.model.enums import RuleMode
from cfripper.model.result import Failure, Result

logger = logging.getLogger(__file__)


class RuleProcessor:
    def __init__(self, *args):
        self.rules = args

    def process_cf_template(self, cfmodel: CFModel, config: Config, extras: Optional[Dict] = None) -> Result:
        result = Result()
        for rule in self.rules:
            if rule.rule_mode == RuleMode.DISABLED:
                continue

            try:
                result += rule.invoke(cfmodel, extras)
            except Exception as other_exception:
                result.add_exception(other_exception)
                logger.exception(
                    "{} crashed with {} for project - {}, service - {}, stack - {}".format(
                        type(rule).__name__,
                        type(other_exception).__name__,
                        config.project_name,
                        config.service_name,
                        config.stack_name,
                    )
                )
                continue
        return result

    @staticmethod
    def remove_debug_rules(rules: List[Failure]):
        return [rule for rule in rules if rule.rule_mode != RuleMode.DEBUG]
