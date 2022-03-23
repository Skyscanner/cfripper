from pytest import fixture

from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rules.sqs_queue_policy import SQSDangerousPolicyActionsRule
from tests.utils import compare_lists_of_failures, get_cfmodel_from


@fixture()
def sqs_policy():
    return get_cfmodel_from("rules/SQSDangerousPolicyActionsRule/sqs_policy.json").resolve()


def test_sqs_dangerous_policy_actions(sqs_policy):
    rule = SQSDangerousPolicyActionsRule(None)
    result = rule.invoke(sqs_policy)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.ACTION,
                reason="SQS Queue policy QueuePolicyPublic1 should not not include the following dangerous actions: ['sqs:AddPermission', 'sqs:CreateQueue', 'sqs:DeleteQueue', 'sqs:RemovePermission', 'sqs:TagQueue']",
                risk_value=RuleRisk.MEDIUM,
                rule="SQSDangerousPolicyActionsRule",
                rule_mode=RuleMode.BLOCKING,
                actions={
                    "sqs:CreateQueue",
                    "sqs:RemovePermission",
                    "sqs:AddPermission",
                    "sqs:DeleteQueue",
                    "sqs:TagQueue",
                },
                resource_ids={"QueuePolicyPublic1"},
                resource_types={"AWS::SQS::QueuePolicy"},
            ),
            Failure(
                granularity=RuleGranularity.ACTION,
                reason="SQS Queue policy QueuePolicyPublic2 should not not include the following dangerous actions: ['sqs:AddPermission', 'sqs:CreateQueue', 'sqs:DeleteQueue', 'sqs:RemovePermission', 'sqs:TagQueue']",
                risk_value=RuleRisk.MEDIUM,
                rule="SQSDangerousPolicyActionsRule",
                rule_mode=RuleMode.BLOCKING,
                actions={
                    "sqs:CreateQueue",
                    "sqs:RemovePermission",
                    "sqs:AddPermission",
                    "sqs:DeleteQueue",
                    "sqs:TagQueue",
                },
                resource_ids={"QueuePolicyPublic2"},
                resource_types={"AWS::SQS::QueuePolicy"},
            ),
            Failure(
                granularity=RuleGranularity.ACTION,
                reason="SQS Queue policy QueuePolicyPublic3 should not not include the following dangerous actions: ['sqs:AddPermission', 'sqs:CreateQueue', 'sqs:DeleteQueue', 'sqs:RemovePermission', 'sqs:TagQueue']",
                risk_value=RuleRisk.MEDIUM,
                rule="SQSDangerousPolicyActionsRule",
                rule_mode=RuleMode.BLOCKING,
                actions={
                    "sqs:CreateQueue",
                    "sqs:RemovePermission",
                    "sqs:AddPermission",
                    "sqs:DeleteQueue",
                    "sqs:TagQueue",
                },
                resource_ids={"QueuePolicyPublic3"},
                resource_types={"AWS::SQS::QueuePolicy"},
            ),
            Failure(
                granularity=RuleGranularity.ACTION,
                reason="SQS Queue policy QueuePolicyPublic4 should not not include the following dangerous actions: ['sqs:AddPermission', 'sqs:CreateQueue', 'sqs:DeleteQueue', 'sqs:RemovePermission', 'sqs:TagQueue']",
                risk_value=RuleRisk.MEDIUM,
                rule="SQSDangerousPolicyActionsRule",
                rule_mode=RuleMode.BLOCKING,
                actions={
                    "sqs:CreateQueue",
                    "sqs:RemovePermission",
                    "sqs:AddPermission",
                    "sqs:DeleteQueue",
                    "sqs:TagQueue",
                },
                resource_ids={"QueuePolicyPublic4"},
                resource_types={"AWS::SQS::QueuePolicy"},
            ),
        ],
    )


def test_rule_supports_filter_config(sqs_policy, default_allow_all_config):
    rule = SQSDangerousPolicyActionsRule(default_allow_all_config)
    result = rule.invoke(sqs_policy)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])
