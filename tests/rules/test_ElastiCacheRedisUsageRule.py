import pytest

from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rules.elasticache_redis_usage import ElastiCacheRedisUsageRule
from tests.utils import get_cfmodel_from


@pytest.fixture()
def redis_cache_cluster():
    return get_cfmodel_from("rules/ElastiCacheRedisUsageRule/redis_cache_cluster.yml").resolve()


@pytest.fixture()
def redis_replication_group():
    return get_cfmodel_from("rules/ElastiCacheRedisUsageRule/redis_replication_group.yml").resolve()


@pytest.fixture()
def memcached_cache_cluster():
    return get_cfmodel_from("rules/ElastiCacheRedisUsageRule/memcached_cache_cluster.yml").resolve()


@pytest.fixture()
def multiple_redis_resources():
    return get_cfmodel_from("rules/ElastiCacheRedisUsageRule/multiple_redis_resources.yml").resolve()


@pytest.fixture()
def no_elasticache_resources():
    return get_cfmodel_from("rules/ElastiCacheRedisUsageRule/no_elasticache_resources.yml").resolve()


@pytest.fixture()
def redis_uppercase():
    return get_cfmodel_from("rules/ElastiCacheRedisUsageRule/redis_uppercase.yml").resolve()


@pytest.fixture()
def valkey_cache_cluster():
    return get_cfmodel_from("rules/ElastiCacheRedisUsageRule/valkey_cache_cluster.yml").resolve()


def test_elasticache_redis_cache_cluster_triggers_rule(redis_cache_cluster):
    """Test that a Redis CacheCluster triggers the rule."""
    rule = ElastiCacheRedisUsageRule(None)
    result = rule.invoke(redis_cache_cluster)

    assert result.valid  # MONITOR mode doesn't invalidate the result
    assert len(result.failures) == 1
    assert result.failures[0] == Failure(
        granularity=RuleGranularity.RESOURCE,
        reason="ElastiCache cluster 'RedisCluster' is using Redis engine. Valkey is now the preferred ElastiCache engine "
        "at Skyscanner. It is fully Redis-compatible and offers improved performance with at least 20% lower cost. "
        "Please use Valkey for all new cache deployments, or for existing Redis OSS caches, consider a cross-upgrade to Valkey.",
        risk_value=RuleRisk.MEDIUM,
        rule="ElastiCacheRedisUsageRule",
        rule_mode=RuleMode.MONITOR,
        actions=None,
        resource_ids={"RedisCluster"},
        resource_types={"AWS::ElastiCache::CacheCluster"},
    )


def test_elasticache_redis_replication_group_triggers_rule(redis_replication_group):
    """Test that a Redis ReplicationGroup triggers the rule."""
    rule = ElastiCacheRedisUsageRule(None)
    result = rule.invoke(redis_replication_group)

    assert result.valid  # MONITOR mode doesn't invalidate the result
    assert len(result.failures) == 1
    assert result.failures[0] == Failure(
        granularity=RuleGranularity.RESOURCE,
        reason="ElastiCache replication group 'RedisReplicationGroup' is using Redis engine. Valkey is now the preferred ElastiCache engine "
        "at Skyscanner. It is fully Redis-compatible and offers improved performance with at least 20% lower cost. "
        "Please use Valkey for all new cache deployments, or for existing Redis OSS caches, consider a cross-upgrade to Valkey.",
        risk_value=RuleRisk.MEDIUM,
        rule="ElastiCacheRedisUsageRule",
        rule_mode=RuleMode.MONITOR,
        actions=None,
        resource_ids={"RedisReplicationGroup"},
        resource_types={"AWS::ElastiCache::ReplicationGroup"},
    )


def test_elasticache_memcached_does_not_trigger_rule(memcached_cache_cluster):
    """Test that a Memcached cluster does not trigger the rule."""
    rule = ElastiCacheRedisUsageRule(None)
    result = rule.invoke(memcached_cache_cluster)

    assert result.valid
    assert len(result.failures) == 0


def test_multiple_redis_resources_trigger_rule(multiple_redis_resources):
    """Test that multiple Redis resources all trigger the rule."""
    rule = ElastiCacheRedisUsageRule(None)
    result = rule.invoke(multiple_redis_resources)

    assert result.valid  # MONITOR mode doesn't invalidate the result
    assert len(result.failures) == 2

    # Check that both resources are flagged
    resource_ids = {next(iter(failure.resource_ids)) for failure in result.failures if failure.resource_ids}
    assert resource_ids == {"RedisCluster1", "RedisReplicationGroup1"}


def test_no_elasticache_resources_valid(no_elasticache_resources):
    """Test that templates without ElastiCache resources are valid."""
    rule = ElastiCacheRedisUsageRule(None)
    result = rule.invoke(no_elasticache_resources)

    assert result.valid
    assert len(result.failures) == 0


def test_elasticache_redis_case_insensitive(redis_uppercase):
    """Test that the rule detects Redis regardless of case."""
    rule = ElastiCacheRedisUsageRule(None)
    result = rule.invoke(redis_uppercase)

    assert result.valid  # MONITOR mode doesn't invalidate the result
    assert len(result.failures) == 1


def test_elasticache_valkey_does_not_trigger_rule(valkey_cache_cluster):
    """Test that a Valkey cluster does not trigger the rule."""
    rule = ElastiCacheRedisUsageRule(None)
    result = rule.invoke(valkey_cache_cluster)

    assert result.valid
    assert len(result.failures) == 0
