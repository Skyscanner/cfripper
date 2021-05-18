<p align="center">
<img src="docs/img/logo.png" width="200">
</p>

# CFRipper

![Build Status](https://github.com/Skyscanner/cfripper/workflows/PyPI%20release/badge.svg)
[![PyPI version](https://badge.fury.io/py/cfripper.svg)](https://badge.fury.io/py/cfripper)
[![Total alerts](https://img.shields.io/lgtm/alerts/g/Skyscanner/cfripper.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/Skyscanner/cfripper/alerts/)
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/Skyscanner/cfripper.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/Skyscanner/cfripper/context:python)

CFRipper is a Library and CLI security analyzer for AWS CloudFormation templates. You can use CFRipper to prevent deploying insecure AWS resources into your Cloud environment. You can write your own compliance checks by adding new custom plugins.

Docs and more details available in https://cfripper.readthedocs.io/

## CLI Usage

### Normal execution

```bash
$ cfripper /tmp/root.yaml /tmp/root_bypass.json --format txt
Analysing /tmp/root.yaml...
Not adding CrossAccountTrustRule failure in rootRole because no AWS Account ID was found in the config.
Valid: False
Issues found:
 - FullWildcardPrincipalRule: rootRole should not allow wildcards in principals (principal: '*')
 - IAMRolesOverprivilegedRule: Role 'rootRole' contains an insecure permission '*' in policy 'root'
Analysing /tmp/root_bypass.json...
Valid: True
```

### Using the "resolve" flag

```bash
$ cfripper /tmp/root.yaml /tmp/root_bypass.json --format txt --resolve
Analysing /tmp/root.yaml...
Not adding CrossAccountTrustRule failure in rootRole because no AWS Account ID was found in the config.
Valid: False
Issues found:
 - FullWildcardPrincipalRule: rootRole should not allow wildcards in principals (principal: '*')
 - IAMRolesOverprivilegedRule: Role 'rootRole' contains an insecure permission '*' in policy 'root'
Analysing /tmp/root_bypass.json...
Not adding CrossAccountTrustRule failure in rootRole because no AWS Account ID was found in the config.
Valid: False
Issues found:
 - IAMRolesOverprivilegedRule: Role 'rootRole' contains an insecure permission '*' in policy 'root'
Monitored issues found:
 - PartialWildcardPrincipalRule: rootRole contains an unknown principal: 123456789012
 - PartialWildcardPrincipalRule: rootRole should not allow wildcard in principals or account-wide principals
(principal: 'arn:aws:iam::123456789012:root')
```

### Using json format and output-folder argument

```bash
$ cfripper /tmp/root.yaml /tmp/root_bypass.json --format json --resolve --output-folder /tmp
Analysing /tmp/root.yaml...
Not adding CrossAccountTrustRule failure in rootRole because no AWS Account ID was found in the config.
Result saved in /tmp/root.yaml.cfripper.results.json
Analysing /tmp/root_bypass.json...
Not adding CrossAccountTrustRule failure in rootRole because no AWS Account ID was found in the config.
Result saved in /tmp/root_bypass.json.cfripper.results.json
```

### Using rules config file

```bash
$ cfripper tests/test_templates/config/security_group_firehose_ips.json --rules-config-file cfripper/config/rule_configs/example_rules_config_for_cli.py
Analysing tests/test_templates/config/security_group_firehose_ips.json...
Valid: True
```

### Using rules filters files

```bash
$ cfripper tests/test_templates/config/security_group_firehose_ips.json --rules-filters-folder cfripper/config/rule_configs/
example_rules_config_for_cli.py loaded
Analysing tests/test_templates/config/security_group_firehose_ips.json...
Valid: True
```

### Exit Codes

```python
"""
Analyse AWS Cloudformation templates passed by parameter.
Exit codes:
  - 0 = all templates valid and scanned successfully
  - 1 = error / issue in scanning at least one template
  - 2 = at least one template is not valid according to CFRipper (template scanned successfully)
  - 3 = unknown / unhandled exception in scanning the templates
"""
```
