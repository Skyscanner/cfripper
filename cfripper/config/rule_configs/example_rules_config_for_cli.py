from cfripper.config.rule_config import RuleConfig
from cfripper.config.rule_configs.firehose_ips import firehose_ips_rules_config_filter
from cfripper.model.enums import RuleMode

RULES_CONFIG = {
    "EC2SecurityGroupMissingEgressRule": RuleConfig(rule_mode=RuleMode.DISABLED),
}

FILTERS = [firehose_ips_rules_config_filter]
