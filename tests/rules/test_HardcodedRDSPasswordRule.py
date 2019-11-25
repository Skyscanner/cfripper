"""
Copyright 2018-2019 Skyscanner Ltd

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
"""
import pytest
from pycfmodel.model.cf_model import CFModel

from cfripper.config.config import Config
from cfripper.model.result import Result
from cfripper.model.utils import convert_json_or_yaml_to_dict
from cfripper.rules.hardcoded_RDS_password import HardcodedRDSPasswordRule
from tests.utils import get_cfmodel_from


@pytest.fixture()
def bad_template_instances():
    return get_cfmodel_from("rules/HardcodedRDSPasswordRule/bad_template.json").resolve()


@pytest.fixture()
def bad_template_clusters():
    return get_cfmodel_from("rules/HardcodedRDSPasswordRule/bad_template_cluster.json").resolve()


@pytest.fixture()
def good_template_clusters_and_instances():
    return get_cfmodel_from("rules/HardcodedRDSPasswordRule/rds_good_cluster_good_instances.json").resolve()


@pytest.fixture()
def bad_template_good_clusters_with_bad_instances():
    return get_cfmodel_from("rules/HardcodedRDSPasswordRule/rds_good_cluster_bad_instances.json").resolve()


@pytest.fixture()
def bad_template_clusters_with_bad_instances():
    return get_cfmodel_from("rules/HardcodedRDSPasswordRule/bad_clusters_and_instances.json").resolve()


def test_failures_are_raised_for_instances(bad_template_instances):
    result = Result()
    rule = HardcodedRDSPasswordRule(None, result)
    rule.invoke(bad_template_instances)

    assert not result.valid
    assert len(result.failed_rules) == 2
    assert len(result.failed_monitored_rules) == 0
    assert result.failed_rules[0].rule == "HardcodedRDSPasswordRule"
    assert result.failed_rules[0].reason == "RDS Instance password parameter missing NoEcho for BadDb3."
    assert result.failed_rules[1].rule == "HardcodedRDSPasswordRule"
    assert result.failed_rules[1].reason == "Default RDS Instance password parameter (readable in plain-text) BadDb5."


def test_failures_are_raised_for_clusters(bad_template_clusters):
    result = Result()
    rule = HardcodedRDSPasswordRule(None, result)
    rule.invoke(bad_template_clusters)

    assert not result.valid
    assert len(result.failed_rules) == 1
    assert len(result.failed_monitored_rules) == 0
    assert result.failed_rules[0].rule == "HardcodedRDSPasswordRule"
    assert result.failed_rules[0].reason == "RDS Cluster password parameter missing NoEcho for BadCluster1."


def test_passed_cluster_pw_protected(good_template_clusters_and_instances):
    result = Result()
    rule = HardcodedRDSPasswordRule(None, result)
    rule.invoke(good_template_clusters_and_instances)

    assert result.valid


def test_failures_are_raised_for_instances_without_protected_clusters(bad_template_good_clusters_with_bad_instances):
    result = Result()
    rule = HardcodedRDSPasswordRule(None, result)
    rule.invoke(bad_template_good_clusters_with_bad_instances)

    assert not result.valid
    assert len(result.failed_rules) == 1
    assert len(result.failed_monitored_rules) == 0
    assert result.failed_rules[0].rule == "HardcodedRDSPasswordRule"
    assert result.failed_rules[0].reason == "Default RDS Instance password parameter (readable in plain-text) BadDb5."


def test_failures_are_raised_for_bad_instances_and_bad_clusters(bad_template_clusters_with_bad_instances):
    result = Result()
    rule = HardcodedRDSPasswordRule(None, result)
    rule.invoke(bad_template_clusters_with_bad_instances)

    assert not result.valid
    assert len(result.failed_rules) == 2
    assert len(result.failed_monitored_rules) == 0
    assert result.failed_rules[0].rule == "HardcodedRDSPasswordRule"
    assert (
        result.failed_rules[0].reason == "Default RDS Cluster password parameter (readable in plain-text) BadCluster99."
    )
    assert result.failed_rules[1].rule == "HardcodedRDSPasswordRule"
    assert result.failed_rules[1].reason == "RDS Instance password parameter missing NoEcho for BadDb33."
