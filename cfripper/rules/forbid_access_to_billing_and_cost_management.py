__all__ = ["ForbidAccessToBillingAndCostManagement"]

from typing import Dict, Optional

from pycfmodel.model.cf_model import CFModel
from pycfmodel.model.resources.iam_managed_policy import IAMManagedPolicy
from pycfmodel.model.resources.iam_policy import IAMPolicy
from pycfmodel.model.resources.iam_role import IAMRole
from pycfmodel.model.resources.iam_user import IAMUser
from pycfmodel.model.resources.properties.policy_document import PolicyDocument
from pycfmodel.model.resources.properties.statement import Statement

from cfripper.model.result import Result
from cfripper.rules.base_rules import Rule


class ForbidAccessToBillingAndCostManagement(Rule):
    """
    Give undesired access to Billing and/or Cost Management

    Risk:
        Give undesired access to Billing and/or Cost Management

    Filters context:
        | Parameter    | Type             | Description                                                     |
        |:------------:|:----------------:|:---------------------------------------------------------------:|
        |`config`      | str              | `config` variable available inside the rule                     |
        |`extras`      | str              | `extras` variable available inside the rule                     |
        |`logical_id`  | str              | ID used in Cloudformation to refer the resource being analysed  |
        |`policy_name` | `Optional[str]`  | If available, the policy name                                   |
        |`statement`   | `Statement`      | Statement being checked found in the Resource                   |
        |`action`      | `str`            | Action that is giving access to billing and cost management     |
    """

    REASON_WITH_POLICY_NAME = '"{}" in "{}" allows access to Billing or Cost Management at "{}"'
    REASON_WITHOUT_POLICY_NAME = '"{}" allows access to Billing or Cost Management at "{}"'

    # List from https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/billing-permissions-ref.html
    BILLING_ACTIONS = (
        "aws-portal:ModifyAccount",
        "aws-portal:ModifyBilling",
        "aws-portal:ModifyPaymentMethods",
        "aws-portal:ViewAccount",
        "aws-portal:ViewBilling",
        "aws-portal:ViewPaymentMethods",
        "aws-portal:ViewUsage",
        "budgets:ModifyBudget",
        "budgets:ViewBudget",
        "ce:CreateAnomalyMonitor",
        "ce:CreateAnomalySubscription",
        "ce:CreateCostCategoryDefinition",
        "ce:DeleteAnomalyMonitor",
        "ce:DeleteAnomalySubscription",
        "ce:DeleteCostCategoryDefinition",
        "ce:DescribeCostCategoryDefinition",
        "ce:GetAnomalies",
        "ce:GetAnomalyMonitors",
        "ce:GetAnomalySubscriptions",
        "ce:ListCostCategoryDefinitions",
        "ce:ProvideAnomalyFeedback",
        "ce:UpdateAnomalyMonitor",
        "ce:UpdateAnomalySubscription",
        "ce:UpdateCostCategoryDefinition",
        "cur:DeleteReportDefinition",
        "cur:DescribeReportDefinitions",
        "cur:ModifyReportDefinition",
        "cur:PutReportDefinition",
        "pricing:DescribeServices",
        "pricing:GetAttributeValues",
        "pricing:GetProducts",
        "purchase-orders:ModifyPurchaseOrders",
        "purchase-orders:ViewPurchaseOrders",
    )

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()
        for logical_id, resource in cfmodel.resources_filtered_by_type((IAMUser, IAMRole, IAMPolicy, IAMManagedPolicy)):
            if isinstance(resource, (IAMUser, IAMRole)) and resource.Properties and resource.Properties.Policies:
                for policy in resource.Properties.Policies:
                    result += self._check_policy_document(logical_id, policy.PolicyDocument, policy.PolicyName, extras)
            elif isinstance(resource, IAMPolicy):
                result += self._check_policy_document(
                    logical_id, resource.Properties.PolicyDocument, resource.Properties.PolicyName, extras
                )
            elif isinstance(resource, IAMManagedPolicy):
                result += self._check_policy_document(
                    logical_id, resource.Properties.PolicyDocument, resource.Properties.ManagedPolicyName, extras,
                )
        return result

    def _check_policy_document(
        self, logical_id: str, policy_document: PolicyDocument, policy_name: Optional[str], extras: Dict
    ) -> Result:
        result = Result()
        for statement in policy_document._statement_as_list():
            self._check_statement(logical_id, policy_name, statement, extras=extras)
        return result

    def _check_statement(
        self, logical_id: str, policy_name: Optional[str], statement: Statement, extras: Dict
    ) -> Result:
        result = Result()

        if statement.Effect and statement.Effect == "Deny":
            return result

        for action in statement.get_expanded_action_list():
            if action in self.BILLING_ACTIONS:
                self.add_failure_to_result(
                    result=result,
                    reason=self._build_reason(logical_id, action, policy_name),
                    resource_ids={logical_id},
                    actions=set(action),
                    context={
                        "config": self._config,
                        "extras": extras,
                        "logical_id": logical_id,
                        "policy_name": policy_name,
                        "statement": statement,
                        "action": action,
                    },
                )
        return result

    def _build_reason(self, logical_id: str, action: str, policy_name: Optional[str]) -> str:
        if policy_name:
            return self.REASON_WITH_POLICY_NAME.format(logical_id, policy_name, action)
        else:
            return self.REASON_WITHOUT_POLICY_NAME.format(logical_id, action)
