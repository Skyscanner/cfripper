from typing import Dict, Optional

from pycfmodel.model.cf_model import CFModel

from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Result
from cfripper.rules.base_rules import Rule


class ElastiCacheRedisUsageRule(Rule):
    """
    Checks if ElastiCache Redis is being used and suggests using Valkey instead.

    Valkey is now the preferred ElastiCache engine at Skyscanner. It is fully Redis-compatible
    and offers improved performance with at least 20% lower cost.

    Risk:
        * MEDIUM: Using Redis instead of Valkey misses cost optimisation opportunities and does not
          align with Skyscanner's preferred cache engine standards.

    Fix:
        * Use Valkey for all new cache deployments
        * For existing Redis OSS caches, consider a cross-upgrade to Valkey

    Filters context:
        | Parameter      | Type             | Description                                                     |
        |:--------------:|:----------------:|:---------------------------------------------------------------:|
        |`config`        | str              | `config` variable available inside the rule                     |
        |`extras`        | str              | `extras` variable available inside the rule                     |
        |`logical_id`    | str              | CloudFormation logical ID of the ElastiCache resource           |
        |`engine`        | str              | The cache engine being used (e.g., 'redis')                     |
        |`resource_type` | str              | The CloudFormation resource type                                |
    """

    RULE_MODE = RuleMode.MONITOR
    RISK_VALUE = RuleRisk.MEDIUM
    GRANULARITY = RuleGranularity.RESOURCE

    REASON_CACHE_CLUSTER = (
        "ElastiCache cluster '{}' is using Redis engine. Valkey is now the preferred ElastiCache engine "
        "at Skyscanner. It is fully Redis-compatible and offers improved performance with at least 20% lower cost. "
        "Please use Valkey for all new cache deployments, or for existing Redis OSS caches, consider a cross-upgrade to Valkey."
    )

    REASON_REPLICATION_GROUP = (
        "ElastiCache replication group '{}' is using Redis engine. Valkey is now the preferred ElastiCache engine "
        "at Skyscanner. It is fully Redis-compatible and offers improved performance with at least 20% lower cost. "
        "Please use Valkey for all new cache deployments, or for existing Redis OSS caches, consider a cross-upgrade to Valkey."
    )

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()

        for logical_id, resource in cfmodel.Resources.items():
            # Check AWS::ElastiCache::CacheCluster resources
            if resource.Type == "AWS::ElastiCache::CacheCluster":
                engine = getattr(resource.Properties, "Engine", "").lower()
                if engine == "redis":
                    self.add_failure_to_result(
                        result,
                        self.REASON_CACHE_CLUSTER.format(logical_id),
                        granularity=self.GRANULARITY,
                        resource_ids={logical_id},
                        resource_types={resource.Type},
                        context={
                            "config": self._config,
                            "extras": extras,
                            "logical_id": logical_id,
                            "engine": engine,
                            "resource_type": resource.Type,
                        },
                    )

            # Check AWS::ElastiCache::ReplicationGroup resources
            elif resource.Type == "AWS::ElastiCache::ReplicationGroup":
                # ReplicationGroups are Redis-only by design (Memcached doesn't support replication)
                # So if a ReplicationGroup exists, it's using Redis
                self.add_failure_to_result(
                    result,
                    self.REASON_REPLICATION_GROUP.format(logical_id),
                    granularity=self.GRANULARITY,
                    resource_ids={logical_id},
                    resource_types={resource.Type},
                    context={
                        "config": self._config,
                        "extras": extras,
                        "logical_id": logical_id,
                        "engine": "redis",
                        "resource_type": resource.Type,
                    },
                )

        return result
