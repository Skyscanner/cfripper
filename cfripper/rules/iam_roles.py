__all__ = ["IAMRolesOverprivilegedRule", "IAMRoleWildcardActionOnPolicyRule"]

from typing import Dict, Optional

from pycfmodel.model.cf_model import CFModel
from pycfmodel.model.resources.iam_managed_policy import IAMManagedPolicy
from pycfmodel.model.resources.iam_role import IAMRole

from cfripper.config.regex import REGEX_IS_STAR, REGEX_WILDCARD_POLICY_ACTION
from cfripper.model.enums import RuleGranularity
from cfripper.model.result import Result
from cfripper.rules.base_rules import Rule


class IAMRolesOverprivilegedRule(Rule):
    """
    Rule that checks for wildcards in resources for a set of actions and restricts managed policies.

    Filters context:
    | Parameter               | Type                             | Description                                                    |
    |:-----------------------:|:--------------------------------:|:--------------------------------------------------------------:|
    |`config`                 | str                              | `config` variable available inside the rule                    |
    |`extras`                 | str                              | `extras` variable available inside the rule                    |
    |`logical_id`             | str                              | ID used in Cloudformation to refer the resource being analysed |
    |`resource`               | `IAMRole`                        | Resource that is being addressed                               |
    |`statement`              | `Optional[Statement]`            | Statement being checked found in the Resource                  |
    |`action`                 | `Optional[str]`                  | Action containing insecure permission with forbidden prefix    |
    """

    GRANULARITY = RuleGranularity.RESOURCE

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, IAMRole):
                self.check_managed_policies(result, logical_id, resource, extras)
                self.check_inline_policies(result, logical_id, resource, extras)
        return result

    def check_managed_policies(self, result: Result, logical_id: str, role: IAMRole, extras: Optional[Dict] = None):
        """Run the managed policies against a blacklist."""
        if not role.Properties.ManagedPolicyArns:
            return

        for managed_policy_arn in role.Properties.ManagedPolicyArns:
            if managed_policy_arn in self._config.forbidden_managed_policy_arns:
                self.add_failure_to_result(
                    result,
                    f"Role {logical_id} has forbidden Managed Policy {managed_policy_arn}",
                    resource_ids={logical_id},
                    resource_types={role.Type},
                    context={
                        "config": self._config,
                        "extras": extras,
                        "logical_id": logical_id,
                        "resource": role,
                        "statement": None,
                        "action": None,
                    },
                )

    def check_inline_policies(self, result: Result, logical_id: str, role: IAMRole, extras: Optional[Dict] = None):
        """Check conditional and non-conditional inline policies."""
        if not role.Properties.Policies:
            return

        for policy in role.Properties.Policies:
            for statement in policy.PolicyDocument.statements_with(REGEX_IS_STAR):
                if statement.Effect and statement.Effect == "Allow":
                    for action in statement.get_action_list():
                        for prefix in self._config.forbidden_resource_star_action_prefixes:
                            if action.startswith(prefix):
                                self.add_failure_to_result(
                                    result,
                                    f"Role '{logical_id}' contains an insecure permission '{action}' in policy "
                                    f"'{policy.PolicyName}'",
                                    resource_ids={logical_id},
                                    resource_types={role.Type},
                                    context={
                                        "config": self._config,
                                        "extras": extras,
                                        "logical_id": logical_id,
                                        "resource": role,
                                        "statement": statement,
                                        "action": action,
                                    },
                                )


class IAMRoleWildcardActionOnPolicyRule(Rule):
    """
    Checks for use of wildcard characters in all IAM Role policies (including `AssumeRolePolicyDocument`)
    and [AWS Managed Policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html).

    Filters context:
        | Parameter           | Type                               | Description                                                    |
        |:-------------------:|:----------------------------------:|:--------------------------------------------------------------:|
        |`config`             | str                                | `config` variable available inside the rule                    |
        |`extras`             | str                                | `extras` variable available inside the rule                    |
        |`logical_id`         | str                                | ID used in Cloudformation to refer the resource being analysed |
        |`resource`           | `Union[IAMRole, IAMManagedPolicy]` | Resource that is being addressed                               |
    """

    GRANULARITY = RuleGranularity.RESOURCE
    REASON = "IAM role {} should not allow a `*` action on its {}"

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()
        for logical_id, resource in cfmodel.Resources.items():
            if isinstance(resource, IAMRole):
                # check AssumeRolePolicyDocument.
                if resource.Properties.AssumeRolePolicyDocument.allowed_actions_with(REGEX_WILDCARD_POLICY_ACTION):
                    self.add_failure_to_result(
                        result,
                        self.REASON.format(logical_id, "AssumeRolePolicy"),
                        resource_ids={logical_id},
                        resource_types={resource.Type},
                        context={
                            "config": self._config,
                            "extras": extras,
                            "logical_id": logical_id,
                            "resource": resource,
                        },
                    )

                # check other policies of the IAM role.
                if resource.Properties.Policies:
                    for policy in resource.Properties.Policies:
                        if policy.PolicyDocument.allowed_actions_with(REGEX_WILDCARD_POLICY_ACTION):
                            self.add_failure_to_result(
                                result,
                                self.REASON.format(logical_id, f"{policy.PolicyName} policy"),
                                resource_ids={logical_id},
                                resource_types={resource.Type},
                                context={
                                    "config": self._config,
                                    "extras": extras,
                                    "logical_id": logical_id,
                                    "resource": resource,
                                },
                            )

            # check AWS::IAM::ManagedPolicy.
            elif isinstance(resource, IAMManagedPolicy) and resource.Properties.PolicyDocument.allowed_actions_with(
                REGEX_WILDCARD_POLICY_ACTION
            ):
                self.add_failure_to_result(
                    result,
                    self.REASON.format(logical_id, "AWS::IAM::ManagedPolicy"),
                    resource_ids={logical_id},
                    resource_types={resource.Type},
                    context={"config": self._config, "extras": extras, "logical_id": logical_id, "resource": resource},
                )
        return result
