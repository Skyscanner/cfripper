from unittest.mock import Mock, patch

import pytest
from pytest import fixture

from cfripper.config.config import Config
from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure, Result
from cfripper.rule_processor import RuleProcessor
from tests.utils import get_fixture_json


@pytest.fixture()
def template():
    return get_fixture_json("rules/CloudFormationAuthenticationRule/cfn_authentication_good.json")


@patch.object(RuleProcessor, "remove_failures_of_whitelisted_resources")
@patch.object(RuleProcessor, "remove_failures_of_whitelisted_actions")
def test_with_no_rules(mock_remove_whitelisted_actions, mock_remove_whitelisted_resources, template):
    processor = RuleProcessor()
    config = Mock()

    processor.process_cf_template(template, config)
    mock_remove_whitelisted_actions.assert_called()
    mock_remove_whitelisted_resources.assert_called()


def test_with_mock_rule(template):
    rule = Mock()

    processor = RuleProcessor(rule)

    config = Mock()
    processor.process_cf_template(template, config)

    rule.invoke.assert_called()


def test_remove_debug_rules():
    original_failed_monitored_rules = [
        Failure(
            rule="a",
            reason="something",
            rule_mode=RuleMode.MONITOR,
            granularity=RuleGranularity.STACK,
            risk_value=RuleRisk.HIGH,
        ),
        Failure(
            rule="b",
            reason="something",
            rule_mode=RuleMode.DEBUG,
            granularity=RuleGranularity.STACK,
            risk_value=RuleRisk.MEDIUM,
        ),
        Failure(
            rule="c",
            reason="something",
            rule_mode=RuleMode.MONITOR,
            granularity=RuleGranularity.STACK,
            risk_value=RuleRisk.LOW,
        ),
    ]

    list_with_no_debug_rules = [original_failed_monitored_rules[0], original_failed_monitored_rules[2]]

    processed_list = RuleProcessor.remove_debug_rules(rules=original_failed_monitored_rules)
    assert list_with_no_debug_rules == processed_list


def test_remove_debug_rules_no_rules():
    processed_list = RuleProcessor.remove_debug_rules(rules=[])
    assert [] == processed_list


@fixture()
def mock_rule_to_resource_whitelist():
    yield {"S3CrossAccountTrustRule": {"teststack": {".*"}, "otherstack": {"rolething"}}}


def test_remove_failures_from_whitelisted_resources_uses_whitelist(mock_rule_to_resource_whitelist):

    config = Config(
        stack_name="otherstack",
        rules=["S3CrossAccountTrustRule"],
        rule_to_resource_whitelist=mock_rule_to_resource_whitelist,
    )

    result = Result()
    result.failed_rules = [
        Failure(
            rule="S3CrossAccountTrustRule",
            reason="rolething has forbidden cross-account policy allow with 123456789 for an S3 bucket.",
            rule_mode=RuleMode.BLOCKING,
            risk_value=RuleRisk.HIGH,
            resource_ids={"rolething"},
            actions=set(),
            granularity=RuleGranularity.RESOURCE,
        ),
        Failure(
            rule="S3CrossAccountTrustRule",
            reason="anotherthing has forbidden cross-account policy allow with 123456789 for an S3 bucket.",
            rule_mode=RuleMode.BLOCKING,
            risk_value=RuleRisk.HIGH,
            resource_ids={"anotherthing"},
            actions=set(),
            granularity=RuleGranularity.RESOURCE,
        ),
    ]

    RuleProcessor.remove_failures_of_whitelisted_resources(config=config, result=result)
    assert result.failed_rules == [
        Failure(
            rule="S3CrossAccountTrustRule",
            reason="anotherthing has forbidden cross-account policy allow with 123456789 for an S3 bucket.",
            rule_mode=RuleMode.BLOCKING,
            risk_value=RuleRisk.HIGH,
            resource_ids={"anotherthing"},
            actions=set(),
            granularity=RuleGranularity.RESOURCE,
        )
    ]


@patch("cfripper.rule_processor.logger.warning")
def test_remove_failures_from_whitelisted_resources_failure_no_resources_is_removed(
    mock_logger, mock_rule_to_resource_whitelist
):
    config = Config(
        stack_name="otherstack",
        rules=["S3CrossAccountTrustRule"],
        rule_to_resource_whitelist=mock_rule_to_resource_whitelist,
    )

    result = Result()
    failure = Failure(
        rule="S3CrossAccountTrustRule",
        reason="rolething has forbidden cross-account policy allow with 123456789 for an S3 bucket.",
        rule_mode=RuleMode.BLOCKING,
        risk_value=RuleRisk.HIGH,
        actions=None,
        granularity=RuleGranularity.RESOURCE,
    )
    result.failed_rules = [failure]

    RuleProcessor.remove_failures_of_whitelisted_resources(config=config, result=result)
    assert result.failed_rules == []
    mock_logger.assert_called_once_with(f"Failure with resource granularity doesn't have resources: {failure}")


def test_remove_failures_from_whitelisted_resources_only_removes_resource_granularity(mock_rule_to_resource_whitelist):
    config = Config(
        stack_name="otherstack",
        rules=["S3CrossAccountTrustRule"],
        rule_to_resource_whitelist=mock_rule_to_resource_whitelist,
    )

    result = Result()
    failed_rules = [
        Failure(
            rule="S3CrossAccountTrustRule",
            reason="rolething has forbidden cross-account policy allow with 123456789 for an S3 bucket.",
            rule_mode=RuleMode.BLOCKING,
            risk_value=RuleRisk.HIGH,
            resource_ids={"rolething"},
            actions=None,
            granularity=RuleGranularity.ACTION,
        ),
        Failure(
            rule="S3CrossAccountTrustRule",
            reason="anotherthing has forbidden cross-account policy allow with 123456789 for an S3 bucket.",
            rule_mode=RuleMode.BLOCKING,
            risk_value=RuleRisk.HIGH,
            resource_ids={"anotherthing"},
            actions=None,
            granularity=RuleGranularity.RESOURCE,
        ),
    ]
    result.failed_rules = failed_rules

    RuleProcessor.remove_failures_of_whitelisted_resources(config=config, result=result)
    assert result.failed_rules == failed_rules


def test_can_whitelist_resource_from_any_stack_if_granularity_is_resource():

    whitelist_for_all_stacks = {
        "S3CrossAccountTrustRule": {".*": {"ProductionAccessTest"}, "otherstack": {"rolething"}}
    }
    config = Config(
        stack_name="abcd", rules=["S3CrossAccountTrustRule"], rule_to_resource_whitelist=whitelist_for_all_stacks
    )

    result = Result()
    failed_rules = [
        Failure(
            rule="S3CrossAccountTrustRule",
            reason="ProductionAccessTest has forbidden cross-account policy allow with 123456789 for an S3 bucket.",
            rule_mode=RuleMode.BLOCKING,
            risk_value=RuleRisk.HIGH,
            resource_ids={"ProductionAccessTest"},
            actions=None,
            granularity=RuleGranularity.RESOURCE,
        ),
        Failure(
            rule="S3CrossAccountTrustRule",
            reason="This one isn't whitelisted because granularity is ACTION and not RESOURCE",
            rule_mode=RuleMode.BLOCKING,
            risk_value=RuleRisk.HIGH,
            resource_ids={"ProductionAccessTest"},
            actions=None,
            granularity=RuleGranularity.ACTION,
        ),
    ]
    result.failed_rules = failed_rules

    RuleProcessor.remove_failures_of_whitelisted_resources(config=config, result=result)
    assert result.failed_rules == [
        Failure(
            rule="S3CrossAccountTrustRule",
            reason="This one isn't whitelisted because granularity is ACTION and not RESOURCE",
            rule_mode=RuleMode.BLOCKING,
            risk_value=RuleRisk.HIGH,
            resource_ids={"ProductionAccessTest"},
            actions=None,
            granularity=RuleGranularity.ACTION,
        )
    ]


def test_only_whitelisted_resources_are_removed(mock_rule_to_resource_whitelist):
    config = Config(
        stack_name="otherstack",
        rules=["S3CrossAccountTrustRule"],
        rule_to_resource_whitelist=mock_rule_to_resource_whitelist,
    )

    result = Result()
    failed_rules = [
        Failure(
            rule="S3CrossAccountTrustRule",
            reason="Forbidden cross-account policy allow with 123456789 for an S3 bucket.",
            rule_mode=RuleMode.BLOCKING,
            risk_value=RuleRisk.HIGH,
            resource_ids={"rolething", "thenotwhitelistedthing", "anotherone"},
            actions=None,
            granularity=RuleGranularity.RESOURCE,
        )
    ]
    result.failed_rules = failed_rules

    RuleProcessor.remove_failures_of_whitelisted_resources(config=config, result=result)
    assert result.failed_rules == [
        Failure(
            rule="S3CrossAccountTrustRule",
            reason="Forbidden cross-account policy allow with 123456789 for an S3 bucket.",
            rule_mode=RuleMode.BLOCKING,
            risk_value=RuleRisk.HIGH,
            resource_ids={"thenotwhitelistedthing", "anotherone"},
            actions=None,
            granularity=RuleGranularity.RESOURCE,
        )
    ]


@fixture()
def mock_rule_to_action_whitelist():
    yield {"WildcardResourceRule": {"teststack": {"s3:*"}, "otherstack": {"dynamodb:*"}}}


def test_remove_failures_from_whitelisted_actions_uses_whitelist(mock_rule_to_action_whitelist):

    config = Config(
        stack_name="teststack", rules=["WildcardResourceRule"], rule_to_action_whitelist=mock_rule_to_action_whitelist
    )

    result = Result()
    result.failed_rules = [
        Failure(
            rule="WildcardResourceRule",
            reason="rolething is using a wildcard resource in BucketAccessPolicy",
            rule_mode=RuleMode.BLOCKING,
            risk_value=RuleRisk.HIGH,
            resource_ids={"BucketAccessPolicy"},
            actions={"s3:Get*"},
            granularity=RuleGranularity.ACTION,
        ),
        Failure(
            rule="WildcardResourceRule",
            reason="rolething is using a wildcard resource in DynamoAccessPolicy",
            rule_mode=RuleMode.BLOCKING,
            risk_value=RuleRisk.HIGH,
            resource_ids={"DynamoAccessPolicy"},
            actions={"dynamodb:Get"},
            granularity=RuleGranularity.ACTION,
        ),
    ]

    RuleProcessor.remove_failures_of_whitelisted_actions(config=config, result=result)
    assert result.failed_rules == [
        Failure(
            rule="WildcardResourceRule",
            reason="rolething is using a wildcard resource in DynamoAccessPolicy",
            rule_mode=RuleMode.BLOCKING,
            risk_value=RuleRisk.HIGH,
            resource_ids={"DynamoAccessPolicy"},
            actions={"dynamodb:Get"},
            granularity=RuleGranularity.ACTION,
        )
    ]


@patch("cfripper.rule_processor.logger.warning")
def test_remove_failures_from_whitelisted_actions_failure_no_actions_is_removed(
    mock_logger, mock_rule_to_action_whitelist
):
    config = Config(
        stack_name="teststack",
        rules=["S3CrossAccountTrustRule"],
        rule_to_action_whitelist=mock_rule_to_action_whitelist,
    )

    result = Result()
    failure = Failure(
        rule="S3CrossAccountTrustRule",
        reason="rolething has forbidden cross-account policy allow with 123456789 for an S3 bucket.",
        rule_mode=RuleMode.BLOCKING,
        risk_value=RuleRisk.HIGH,
        actions=set(),
        granularity=RuleGranularity.ACTION,
    )
    result.failed_rules = [failure]

    RuleProcessor.remove_failures_of_whitelisted_actions(config=config, result=result)
    assert result.failed_rules == []
    mock_logger.assert_called_once_with(f"Failure with action granularity doesn't have actions: {failure}")


def test_remove_failures_from_whitelisted_actions_only_removes_action_granularity(mock_rule_to_action_whitelist):
    config = Config(
        stack_name="teststack",
        rules=["S3CrossAccountTrustRule"],
        rule_to_action_whitelist=mock_rule_to_action_whitelist,
    )

    result = Result()
    failed_rules = [
        Failure(
            rule="WildcardResourceRule",
            reason="rolething is using a wildcard resource in BucketAccessPolicy",
            rule_mode=RuleMode.BLOCKING,
            risk_value=RuleRisk.HIGH,
            resource_ids={"BucketAccessPolicy"},
            actions={"s3:Get*"},
            granularity=RuleGranularity.ACTION,
        ),
        Failure(
            rule="WildcardResourceRule",
            reason="rolething is using a wildcard resource in BucketAccessPolicy",
            rule_mode=RuleMode.BLOCKING,
            risk_value=RuleRisk.HIGH,
            resource_ids=set(),
            actions=set(),
            granularity=RuleGranularity.STACK,
        ),
    ]
    result.failed_rules = failed_rules

    RuleProcessor.remove_failures_of_whitelisted_actions(config=config, result=result)
    assert result.failed_rules == [
        Failure(
            rule="WildcardResourceRule",
            reason="rolething is using a wildcard resource in BucketAccessPolicy",
            rule_mode=RuleMode.BLOCKING,
            risk_value=RuleRisk.HIGH,
            resource_ids=set(),
            actions=set(),
            granularity=RuleGranularity.STACK,
        )
    ]


def test_can_whitelist_action_from_any_stack_if_granularity_is_action():

    whitelist_for_all_stacks = {"S3CrossAccountTrustRule": {".*": {"s3:ListBucket"}}}
    config = Config(
        stack_name="abcd", rules=["S3CrossAccountTrustRule"], rule_to_action_whitelist=whitelist_for_all_stacks
    )

    result = Result()
    failed_rules = [
        Failure(
            rule="S3CrossAccountTrustRule",
            reason="ProductionAccessTest has forbidden cross-account policy allow with 123456789 for an S3 bucket.",
            rule_mode=RuleMode.BLOCKING,
            risk_value=RuleRisk.HIGH,
            actions={"s3:ListBucket"},
            granularity=RuleGranularity.ACTION,
        ),
        Failure(
            rule="S3CrossAccountTrustRule",
            reason="This one isn't whitelisted because granularity is STACK and not ACTION",
            rule_mode=RuleMode.BLOCKING,
            risk_value=RuleRisk.HIGH,
            actions=set(),
            granularity=RuleGranularity.STACK,
        ),
    ]
    result.failed_rules = failed_rules

    RuleProcessor.remove_failures_of_whitelisted_actions(config=config, result=result)
    assert result.failed_rules == [
        Failure(
            rule="S3CrossAccountTrustRule",
            reason="This one isn't whitelisted because granularity is STACK and not ACTION",
            rule_mode=RuleMode.BLOCKING,
            risk_value=RuleRisk.HIGH,
            actions=set(),
            granularity=RuleGranularity.STACK,
        )
    ]


def test_action_whitelist_keeps_non_whitelisted_actions():
    whitelist_for_all_stacks = {"MockRule": {".*": {"s3:List"}}}
    config = Config(stack_name="abcd", rules=["MockRule"], rule_to_action_whitelist=whitelist_for_all_stacks)

    result = Result()
    failed_rules = [
        Failure(
            rule="MockRule",
            reason="MockRule is invalid for some actions",
            rule_mode=RuleMode.BLOCKING,
            risk_value=RuleRisk.HIGH,
            actions={"s3:ListBucket", "s3:GetBucket"},
            granularity=RuleGranularity.ACTION,
        )
    ]
    result.failed_rules = failed_rules

    RuleProcessor.remove_failures_of_whitelisted_actions(config=config, result=result)
    assert result.failed_rules == [
        Failure(
            rule="MockRule",
            reason="MockRule is invalid for some actions",
            rule_mode=RuleMode.BLOCKING,
            risk_value=RuleRisk.HIGH,
            actions={"s3:GetBucket"},
            granularity=RuleGranularity.ACTION,
        )
    ]
