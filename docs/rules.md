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

## Custom Rules

To add custom rules first extend the [Rule](https://github.com/Skyscanner/cfripper/blob/master/cfripper/model/rule.py)
class. Then implement the `invoke` method by adding your logic.

{{ inline_source('cfripper.rules.base_rules.Rule.invoke') }}

CFRipper uses [pycfmodel](https://github.com/Skyscanner/pycfmodel) to create a Python model of the CloudFormation script.
This model is passed to the `invoke` function as the `cfmodel` parameter. You can use the model's iterate through the
resources and other objects of the model and use the helper functions to perform various checks. Look at the
[current rules](cfripper/rules) for examples.

{{ inline_source('cfripper.rules.cross_account_trust.S3CrossAccountTrustRule') }}

## Monitor Mode

By default, each rule has `MONITOR_MODE` set to false. Monitor model will return the failed rules in another field in the
response, instead in the main "failed rules". This way new rules can be tested before they are removed from monitor
mode and start triggering alarms.
