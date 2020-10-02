Allows to overwrite the default behaviour of the rule, such as changing the rule mode and risk value. It accepts a more
 granular configuration using the filter.
 
{{ inline_source('cfripper.config.rule_config.RuleConfig') }}

## Filters

When adding a failure or warning it will check if there is a filter that matches the current context and set the new 
risk or mode. Context depends on each rule and is available inside each rule's documentation.
The object accepts a reason parameter to say why that filter exists.

{{ inline_source('cfripper.config.filter.Filter') }}

!!! warning
    Only available for the following rules: 
    
      - CrossAccountCheckingRule
      - CrossAccountTrustRule
      - EC2SecurityGroupIngressOpenToWorldRule
      - EC2SecurityGroupMissingEgressRule
      - EC2SecurityGroupOpenToWorldRule
      - KMSKeyCrossAccountTrustRule
      - S3CrossAccountTrustRule
      - WildcardResourceRule
      
### Filter preference

Following the cascade style, takes preference always the last value set following this structure:

```
Rule Standard -> Rule Config -> Filter #1 -> ... -> Filter #N
```
 

### Implemented filter functions
|  Function           |   Description                                                               |  Example                                | 
|:-------------------:|:---------------------------------------------------------------------------:|:---------------------------------------:|
| `eq`                | Same as a == b                                                              | `{"eq": ["string", "string"]}`          |
| `ne`                | Same as a != b                                                              | `{"ne": ["string", "not_that_string"]}` |
| `lt`                | Same as a < b                                                               | `{"lt": [0, 1]}`                        |
| `gt`                | Same as a > b                                                               | `{"gt": [1, 0]}`                        |
| `le`                | Same as a <= b                                                              | `{"le": [1, 1]}`                        |
| `ge`                | Same as a >= b                                                              | `{"ge": [1, 1]}`                        |
| `not`               | Same as not a                                                               | `{"not": True}`                         |
| `or`                | True if any arg is True                                                     | `{"or": [False, True]}`                 |
| `and`               | True if all args are True                                                   | `{"and": [True, True]}`                 |
| `in`                | Same as a in b                                                              | `{"in": ["b", ["a", "b"]]}`             |
| `regex`             | True if b match pattern a (case sensitive)                                  | `{"regex": [r"^\d+$", "5"]}`            |
| `regex:ignorecase`  | True if b match pattern a (case insensitive)                                | `{"regex:ignorecase": [r"^AA$", "aa"]}` |
| `exists`            | True if a is not None                                                       | `{"exists": None}`                      |
| `empty`             | True if len(a) equals 0                                                     | `{"empty": []}`                         |
| `ref`               | Get the value at any depth of the context based on the path described by a. | `{"ref": "param_a.param_b"}`            |

### Examples

Disable the rule if the role name is prefixed with `sandbox-` and the principal equals `arn:aws:iam::123456789012:role/test-role`.
```python3
Filter(
    reason="",
    rule_mode=RuleMode.DISABLED,
    eval={
        "and": [
            {"regex": ["^sandbox-.*$", {"ref": "resource.Properties.RoleName"}]},
            {"eq": [{"ref": "principal"}, "arn:aws:iam::123456789012:role/test-role"]},
        ]
    },
)
```

