__all__ = ["WildcardResourceRule"]
import json
import logging
from typing import Dict, Optional

from pycfmodel.model.resources.generic_resource import GenericResource
from pycfmodel.model.resources.iam_role import IAMRole
from pycfmodel.model.resources.properties.policy_document import PolicyDocument
from pycfmodel.model.resources.properties.statement import Statement
from pycfmodel.model.resources.resource import Resource

from cfripper.cloudformation_actions_only_accepts_wildcard import CLOUDFORMATION_ACTIONS_ONLY_ACCEPTS_WILDCARD
from cfripper.config.regex import REGEX_IS_STAR, REGEX_WILDCARD_ARN
from cfripper.model.enums import RuleGranularity, RuleMode
from cfripper.model.result import Result
from cfripper.rules.base_rules import ResourceSpecificRule

logger = logging.getLogger(__file__)


class WildcardResourceRule(ResourceSpecificRule):
    """
    Generic rule that detects actions that accept a resource and are using a wildcard.

    Risk:
        Give roles access to undesired resources.

    Fix:
        Check AWS docs to use the recommended resource value.

    Filters context:
        | Parameter    | Type             | Description                                                     |
        |:------------:|:----------------:|:---------------------------------------------------------------:|
        |`config`      | `str`            | `config` variable available inside the rule                     |
        |`extras`      | `str`            | `extras` variable available inside the rule                     |
        |`logical_id`  | `str`            | ID used in CloudFormation to refer the resource being analysed  |
        |`policy_name` | `Optional[str]`  | If available, the policy name                                   |
        |`statement`   | `Statement`      | Statement being checked found in the Resource                   |
        |`action`      | `Optional[str]`  | Action that has a wildcard resource. If None, means all actions |
    """

    RESOURCE_TYPES = (Resource,)
    REASON_WITH_POLICY_NAME = '"{}" is using a wildcard resource in "{}" for "{}"'
    REASON_WITHOUT_POLICY_NAME = '"{}" is using a wildcard resource for "{}"'
    REASON_ALL_ACTIONS_WITH_POLICY_NAME = '"{}" is using a wildcard resource in "{}" allowing all actions'
    REASON_ALL_ACTIONS_WITHOUT_POLICY_NAME = '"{}" is using a wildcard resource allowing all actions'

    def resource_invoke(self, resource: Resource, logical_id: str, extras: Optional[Dict] = None) -> Result:
        """
        Checks each policy of a given resource.
        If it's an IAMRole, it will check its AssumeRolePolicyDocument as well.
        There are some cases where GenericResource contains a property called PolicyDocument that can be a str and
        therefore, it's not being retrieved in the initial for loop.
        For those cases, we run another check transforming the str to a PolicyDocument.
        """
        result = Result()

        for policy in resource.policy_documents:
            self._check_policy_document(
                result, logical_id, policy.policy_document, policy.name, extras, resource_type=resource.Type
            )

        if isinstance(resource, IAMRole):
            self._check_policy_document(
                result,
                logical_id,
                resource.Properties.AssumeRolePolicyDocument,
                None,
                extras,
                resource_type=resource.Type,
            )
        elif isinstance(resource, GenericResource):
            policy_document = getattr(resource.Properties, "PolicyDocument", None)
            if policy_document:
                try:
                    formatted_policy_document = (
                        json.loads(policy_document) if isinstance(policy_document, str) else policy_document
                    )
                    self._check_policy_document(
                        result,
                        logical_id,
                        PolicyDocument(**formatted_policy_document),
                        None,
                        extras,
                        resource_type=resource.Type,
                    )
                except Exception:
                    logger.warning(
                        f"Could not process the PolicyDocument {policy_document} on {logical_id}", stack_info=True
                    )

        return result

    def _check_policy_document(
        self,
        result: Result,
        logical_id: str,
        policy_document: PolicyDocument,
        policy_name: Optional[str],
        extras: Dict,
        resource_type: str,
    ):
        statements_to_review = policy_document.statements_with(REGEX_IS_STAR) + policy_document.statements_with(
            REGEX_WILDCARD_ARN
        )
        for statement in statements_to_review:
            self._check_statement(
                result, logical_id, policy_name, statement, extras=extras, resource_type=resource_type
            )

    def _check_statement(
        self,
        result: Result,
        logical_id: str,
        policy_name: Optional[str],
        statement: Statement,
        extras: Dict,
        resource_type: str,
    ):
        if statement.Effect and statement.Effect == "Deny":
            return

        if statement.actions_with(REGEX_IS_STAR):
            if statement.Condition:
                self._add_to_result(
                    result, logical_id, policy_name, None, statement, extras, monitor=True, resource_type=resource_type
                )
            else:
                self._add_to_result(
                    result, logical_id, policy_name, None, statement, extras, resource_type=resource_type
                )
        else:
            for action in statement.get_expanded_action_list():
                if action in CLOUDFORMATION_ACTIONS_ONLY_ACCEPTS_WILDCARD:
                    logger.info(f"Action {action} only accepts wildcard, ignoring...")
                elif action.lower().startswith("kms:"):
                    # When KMS Key policies use * in the resource, that * will only apply this policy to the KMS Key
                    # being created so, we must not flag this
                    # Source: https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html
                    logger.info(f"KMS Action {action} only accepts wildcard, ignoring...")
                elif statement.Condition:
                    self._add_to_result(
                        result,
                        logical_id,
                        policy_name,
                        action,
                        statement,
                        extras,
                        monitor=True,
                        resource_type=resource_type,
                    )
                else:
                    self._add_to_result(
                        result, logical_id, policy_name, action, statement, extras, resource_type=resource_type
                    )

    def _add_to_result(
        self,
        result: Result,
        logical_id: str,
        policy_name: Optional[str],
        action: Optional[str],
        statement: Statement,
        extras: Dict,
        resource_type: str,
        monitor: bool = False,
    ):
        self.add_failure_to_result(
            result=result,
            reason=self._build_reason(logical_id, action, policy_name),
            granularity=RuleGranularity.ACTION,
            resource_ids={logical_id},
            resource_types={resource_type},
            actions=set(statement.get_action_list()),
            rule_mode=RuleMode.MONITOR if monitor else None,
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
