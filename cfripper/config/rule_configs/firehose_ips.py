from cfripper.config.filter import Filter
from cfripper.model.enums import RuleMode

"""
To use this Filter, or any Filter, make sure to include it in the `Config` instantiation.

```python
FILTERS = [firehose_ips_rules_config_filter]

config = Config(
    ...
    rules_filters=FILTERS,
)
```
"""

# Adapted from https://docs.aws.amazon.com/firehose/latest/dev/controlling-access.html
FIREHOSE_IPS = {
    "13.113.196.224/27",  # Asia Pacific (Tokyo)
    "13.209.1.64/27",  # Asia Pacific (Seoul)
    "13.210.67.224/27",  # Asia Pacific (Sydney)
    "13.228.64.192/27",  # Asia Pacific (Singapore)
    "13.232.67.32/27",  # Asia Pacific (Mumbai)
    "13.244.121.224/277",  # Africa (Cape Town)
    "13.53.63.224/27",  # Europe (Stockholm)
    "13.57.135.192/27",  # US West (N. California)
    "13.58.135.96/27",  # US East (Ohio)
    "15.161.135.128/27",  # Europe (Milan)
    "15.185.91.0/27",  # Middle East (Bahrain)
    "161.189.23.64/27",  # China (Ningxia)
    "18.130.1.96/27",  # Europe (London)
    "18.162.221.32/27",  # Asia Pacific (Hong Kong)
    "18.228.1.128/27",  # South America (São Paulo)
    "18.253.138.96/27",  # AWS GovCloud (US-East)
    "35.158.127.160/27",  # Europe (Frankfurt)
    "35.180.1.96/27",  # Europe (Paris)
    "35.183.92.128/27",  # Canada (Central)
    "52.19.239.192/27",  # Europe (Ireland)
    "52.61.204.160/27",  # AWS GovCloud (US-West)
    "52.70.63.192/27",  # US East (N. Virginia)
    "52.81.151.32/27",  # China (Beijing)
    "52.89.255.224/27",  # US West (Oregon)
}

firehose_ips_rules_config_filter = Filter(
    reason=(
        "Exclude Kinesis Data Firehose IPs to allow access from Amazon Redshift Clusters. "
        "See https://docs.aws.amazon.com/firehose/latest/dev/controlling-access.html"
    ),
    rule_mode=RuleMode.ALLOWED,
    eval={"and": [{"exists": {"ref": "ingress_ip"}}, {"in": [{"ref": "ingress_ip"}, FIREHOSE_IPS]}]},
    rules={"EC2SecurityGroupOpenToWorldRule"},
)
