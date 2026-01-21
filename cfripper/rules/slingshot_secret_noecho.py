__all__ = ["SlingshotSecretNoEchoRule"]

from inspect import Parameter
from typing import Any, Dict, Optional

from pycfmodel.model.cf_model import CFModel

from cfripper.model.enums import RuleGranularity
from cfripper.model.result import Result
from cfripper.rules.base_rules import Rule


class SlingshotSecretNoEchoRule(Rule):
    """
    Ensure parameters receiving Slingshot secrets have NoEcho enabled.

    Risk:
        Secrets passed via Slingshot are substituted into parameters. If the
        parameter is not declared with NoEcho, the secret can appear in clear
        text in the AWS console, logs, or change sets.

    Fix:
        Set NoEcho: true on any parameter that receives a Slingshot secret
        (`<SECRET:...>` placeholder).

    Code for fix:
        ````yml
        Parameters:
          DBPassword:
            NoEcho: true
            Type: String
        ````

    Filters context:
        | Parameter          | Type        | Description                                   |
        |:------------------:|:-----------:|:---------------------------------------------:|
        |`config`            | Config      | `config` variable available inside the rule   |
        |`extras`            | dict        | `extras` variable available inside the rule   |
        |`parameter`         | Parameter   | Parameter object from the template (or None)  |
        |`parameter_name`    | str         | Name of the parameter being checked           |
    """

    REASON = "Parameter {} contains a Slingshot secret but NoEcho is not set."
    GRANULARITY = RuleGranularity.STACK

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()

        stack_parameters = self._get_stack_parameters(extras)
        if not stack_parameters:
            return result

        template_parameters = cfmodel.Parameters or {}

        for param_name, param_value in stack_parameters.items():
            if not self._is_secret_placeholder(param_value):
                continue

            template_param = template_parameters.get(param_name)
            if not self._has_noecho(template_param):
                self.add_failure_to_result(
                    result,
                    self.REASON.format(param_name),
                    resource_ids={param_name},
                    context={
                        "config": self._config,
                        "extras": extras,
                        "parameter": template_param,
                        "parameter_name": param_name,
                    },
                )

        return result

    @staticmethod
    def _get_stack_parameters(extras: Optional[Dict]) -> Dict[str, Any]:
        if not extras:
            return {}
        return extras.get("stack", {}).get("parameters", {})

    @staticmethod
    def _is_secret_placeholder(value: Any) -> bool:
        """Check if value contains a Slingshot secret (<SECRET:xxx>) placeholder."""
        return isinstance(value, str) and "<SECRET:" in value

    @staticmethod
    def _has_noecho(parameter: Parameter) -> bool:
        if parameter is None:
            return False
        return getattr(parameter, "NoEcho", False) is True
