__all__ = [
    "WildcardResourceRule",
]
import logging
from typing import Dict, Optional

from pycfmodel.model.cf_model import CFModel
from pycfmodel.model.resources.generic_resource import GenericResource
from pycfmodel.model.resources.iam_role import IAMRole
from pycfmodel.model.resources.kms_key import KMSKey
from pycfmodel.model.resources.properties.policy_document import PolicyDocument
from pycfmodel.model.resources.properties.statement import Statement

from cfripper.cloudformation_actions_only_accepts_wildcard import CLOUDFORMATION_ACTIONS_ONLY_ACCEPTS_WILDCARD
from cfripper.config.regex import REGEX_IS_STAR
from cfripper.model.enums import RuleGranularity
from cfripper.model.result import Result
from cfripper.rules.base_rules import Rule

logger = logging.getLogger(__file__)


class WildcardResourceRule(Rule):
    """
    Generic rule that detects actions that accept a resource and are using a wildcard.

    Risk:
        Give roles access to undesired resources.

    Fix:
        Check AWS docs to use the recommended resource value.

    Filters context:
        | Parameter    | Type             | Description                                                     |
        |:------------:|:----------------:|:---------------------------------------------------------------:|
        |`config`      | str              | `config` variable available inside the rule                     |
        |`extras`      | str              | `extras` variable available inside the rule                     |
        |`logical_id`  | str              | ID used in Cloudformation to refer the resource being analysed  |
        |`policy_name` | `Optional[str]`  | If available, the policy name                                   |
        |`statement`   | `Statement`      | Statement being checked found in the Resource                   |
        |`action`      | `Optional[str]`  | Action that has a wildcard resource. If None, means all actions |
    """

    REASON_WITH_POLICY_NAME = '"{}" is using a wildcard resource in "{}" for "{}"'
    REASON_WITHOUT_POLICY_NAME = '"{}" is using a wildcard resource for "{}"'
    REASON_ALL_ACTIONS_WITH_POLICY_NAME = '"{}" is using a wildcard resource in "{}" allowing all actions'
    REASON_ALL_ACTIONS_WITHOUT_POLICY_NAME = '"{}" is using a wildcard resource allowing all actions'

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()
        for logical_id, resource in cfmodel.Resources.items():
            for policy in resource.policy_documents:
                self._check_policy_document(result, logical_id, policy.policy_document, policy.name, extras)
            if isinstance(resource, IAMRole):
                self._check_policy_document(
                    result, logical_id, resource.Properties.AssumeRolePolicyDocument, None, extras
                )
            elif isinstance(resource, KMSKey):
                self._check_policy_document(result, logical_id, resource.Properties.KeyPolicy, None, extras)
            elif isinstance(resource, GenericResource):
                if hasattr(resource, "Properties"):
                    policy_document = resource.Properties.get("PolicyDocument")
                    if policy_document:
                        self._check_policy_document(result, logical_id, PolicyDocument(**policy_document), None, extras)
        return result

    def _check_policy_document(
        self, result: Result, logical_id: str, policy_document: PolicyDocument, policy_name: Optional[str], extras: Dict
    ):
        for statement in policy_document.statements_with(REGEX_IS_STAR):
            self._check_statement(result, logical_id, policy_name, statement, extras=extras)

    def _check_statement(
        self, result: Result, logical_id: str, policy_name: Optional[str], statement: Statement, extras: Dict
    ):
        if statement.Effect and statement.Effect == "Deny":
            return

        if statement.actions_with(REGEX_IS_STAR):
            if statement.Condition:
                self._add_to_result(result, logical_id, policy_name, None, statement, extras, warning=True)
            else:
                self._add_to_result(result, logical_id, policy_name, None, statement, extras)
        else:
            for action in statement.get_expanded_action_list():
                if action in CLOUDFORMATION_ACTIONS_ONLY_ACCEPTS_WILDCARD:
                    logger.info(f"Action {action} only accepts wildcard, ignoring...")
                elif action.lower().startswith("kms:"):
                    # When KMS Key policies use * in the resource, that * will only apply this policy to the KMS Key being created
                    # so we must not flag this
                    # Source: https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html
                    logger.info(f"KMS Action {action} only accepts wildcard, ignoring...")
                elif statement.Condition:
                    self._add_to_result(result, logical_id, policy_name, action, statement, extras, warning=True)
                else:
                    self._add_to_result(result, logical_id, policy_name, action, statement, extras)

    def _add_to_result(
        self,
        result: Result,
        logical_id: str,
        policy_name: Optional[str],
        action: Optional[str],
        statement: Statement,
        extras: Dict,
        warning: bool = False,
    ):
        add_to_result = self.add_warning_to_result if warning else self.add_failure_to_result
        add_to_result(
            result=result,
            reason=self._build_reason(logical_id, action, policy_name),
            granularity=RuleGranularity.ACTION,
            resource_ids={logical_id},
            actions=set(statement.get_action_list()),
            context={
                "config": self._config,
                "extras": extras,
                "logical_id": logical_id,
                "policy_name": policy_name,
                "statement": statement,
                "action": action,
            },
        )

    def _build_reason(self, logical_id: str, action: Optional[str], policy_name: Optional[str]) -> str:
        if action:
            if policy_name:
                return self.REASON_WITH_POLICY_NAME.format(logical_id, policy_name, action)
            else:
                return self.REASON_WITHOUT_POLICY_NAME.format(logical_id, action)
        else:
            if policy_name:
                return self.REASON_ALL_ACTIONS_WITH_POLICY_NAME.format(logical_id, policy_name)
            else:
                return self.REASON_ALL_ACTIONS_WITHOUT_POLICY_NAME.format(logical_id)
