Rules are the heart of CFRipper.
When running CFRipper the CloudFormation stack will be checked against each rule and the results combined.

## Available Rules

{% for rule in cfripper_rules() -%}

### {{ rule.0 }}

{% if rule.1 -%}
{{ rule.1 }}
{% endif -%}
---
{% endfor %}

## Monitor Mode

By default, each rule has `MONITOR_MODE` set to false. Monitor model will return the failed rules in another field in the
response, instead in the main "failed rules". This way new rules can be tested before they are removed from monitor
mode and start triggering alarms.
