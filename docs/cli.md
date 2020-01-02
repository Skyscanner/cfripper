# CLI

```bash
{{ cfripper_cli_help() }}
```

## Examples

### Normal execution
```bash
$ cfripper /tmp/root.yaml /tmp/root_bypass.json --format txt
Analysing /tmp/root.yaml...
Not adding CrossAccountTrustRule failure in rootRole because no AWS Account ID was found in the config.
Valid: False
IAMRolesOverprivilegedRule: Role 'rootRole' contains an insecure permission '*' in policy 'root'
FullWildcardPrincipalRule: rootRole should not allow wildcards in principals (principal: '*')

Analysing /tmp/root_bypass.json...
Valid: True
```

### Using resolve flag
```bash
$ cfripper /tmp/root.yaml /tmp/root_bypass.json --format txt --resolve
Analysing /tmp/root.yaml...
Not adding CrossAccountTrustRule failure in rootRole because no AWS Account ID was found in the config.
Valid: False
IAMRolesOverprivilegedRule: Role 'rootRole' contains an insecure permission '*' in policy 'root'
FullWildcardPrincipalRule: rootRole should not allow wildcards in principals (principal: '*')

Analysing /tmp/root_bypass.json...
Not adding CrossAccountTrustRule failure in rootRole because no AWS Account ID was found in the config.
Valid: False
IAMRolesOverprivilegedRule: Role 'rootRole' contains an insecure permission '*' in policy 'root'
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