from cfripper.config.filter import Filter
from cfripper.model.enums import RuleMode

"""
To use this RuleConfig, or any RuleConfig, make sure to include it in the `Config` instantiation.

```python
RULES_CONFIG = {
    "EC2SecurityGroupOpenToWorldRule": RuleConfig(
        filters=[firehose_ips_rules_config_filter]
    )
}

config = Config(
    ...
    rules_config=RULES_CONFIG,
)
```
"""

# Adapted from https://docs.aws.amazon.com/firehose/latest/dev/controlling-access.html
FIREHOSE_IPS = [
    "13.58.135.96/27",
    "52.70.63.192/27",
    "13.57.135.192/27",
    "52.89.255.224/27",
    "18.253.138.96/27",
    "52.61.204.160/27",
    "35.183.92.128/27",
    "18.162.221.32/27",
    "13.232.67.32/27",
    "13.209.1.64/27",
    "13.228.64.192/27",
    "13.210.67.224/27",
    "13.113.196.224/27",
    "52.81.151.32/27",
    "161.189.23.64/27",
    "35.158.127.160/27",
    "52.19.239.192/27",
    "18.130.1.96/27",
    "35.180.1.96/27",
    "13.53.63.224/27",
    "15.185.91.0/27",
    "18.228.1.128/27",
    "15.161.135.128/27",
    "13.244.121.224/27",
]

firehose_ips_rules_config_filter = Filter(
    reason=(
        "Exclude Kinesis Data Firehose IPs to allow access from Amazon Redshift Clusters. "
        "See https://docs.aws.amazon.com/firehose/latest/dev/controlling-access.html"
    ),
    rule_mode=RuleMode.WHITELISTED,
    eval={"and": [{"exists": {"ref": "ingress_ip"}}, {"in": [{"ref": "ingress_ip"}, FIREHOSE_IPS]}]},
)
