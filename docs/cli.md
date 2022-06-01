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
Issues found:
	- FullWildcardPrincipalRule: rootRole should not allow full wildcard '*', or wildcard in account ID like 'arn:aws:iam::*:12345' at '*'
	- IAMRolesOverprivilegedRule: Role 'rootRole' contains an insecure permission '*' in policy 'root'
Analysing /tmp/root_bypass.json...
Valid: True
```

### Using resolve flag
```bash
$ cfripper /tmp/root.yaml /tmp/root_bypass.json --format txt --resolve
Analysing /tmp/root.yaml...
Not adding CrossAccountTrustRule failure in rootRole because no AWS Account ID was found in the config.
Valid: False
Issues found:
	- FullWildcardPrincipalRule: rootRole should not allow full wildcard '*', or wildcard in account ID like 'arn:aws:iam::*:12345' at '*'
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

### Using the "aws-account-id" and "aws-principals" arguments

- `--aws-account-id` is used to specify the AWS Account you want to check the template against
- `--aws-principals` is used to specify the expected/allowed principals to ignore when checking the template 

See how the output is reduced as each option is added:

Without either argument, 13 issues:
```bash
$ cfripper ./tests/test_templates/rules/S3CrossAccountTrustRule/s3_bucket_cross_account_and_normal.json --format txt --resolve
Analysing ./tests/test_templates/rules/S3CrossAccountTrustRule/s3_bucket_cross_account_and_normal.json...
Using `UNDEFINED_PARAM_S3Bucket` for S3Bucket. Original value wasn't available.
Not adding S3CrossAccountTrustRule failure in S3BucketPolicyAccountAccess because no AWS Account ID was found in the config.
Not adding S3CrossAccountTrustRule failure in S3BucketPolicyAccountAccess because no AWS Account ID was found in the config.
Not adding S3CrossAccountTrustRule failure in S3BucketPolicyAccountAccess because no AWS Account ID was found in the config.
Not adding S3CrossAccountTrustRule failure in S3BucketPolicyAccountAccess because no AWS Account ID was found in the config.
Valid: False
Issues found:
	- PartialWildcardPrincipalRule: S3BucketPolicyAccountAccess should not allow wildcard, account-wide or root in resource-id like 'arn:aws:iam::12345:root' at 'arn:aws:iam::123456789012:role/some-role/some-other-sub-role'
	- PartialWildcardPrincipalRule: S3BucketPolicyAccountAccess should not allow wildcard, account-wide or root in resource-id like 'arn:aws:iam::12345:root' at 'arn:aws:iam::666555444333:root'
	- S3BucketPolicyPrincipalRule: S3 Bucket S3BucketPolicyAccountAccess policy has non-allowed principals 123456789012
	- S3BucketPolicyPrincipalRule: S3 Bucket S3BucketPolicyAccountAccess policy has non-allowed principals 123456789012
	- S3BucketPolicyPrincipalRule: S3 Bucket S3BucketPolicyAccountAccess policy has non-allowed principals 123456789012
	- S3BucketPolicyPrincipalRule: S3 Bucket S3BucketPolicyAccountAccess policy has non-allowed principals 123456789012
	- S3BucketPolicyPrincipalRule: S3 Bucket S3BucketPolicyAccountAccess policy has non-allowed principals 123456789012
	- S3BucketPolicyPrincipalRule: S3 Bucket S3BucketPolicyAccountAccess policy has non-allowed principals 123456789012
	- S3BucketPolicyPrincipalRule: S3 Bucket S3BucketPolicyAccountAccess policy has non-allowed principals 123456789012
	- S3BucketPolicyPrincipalRule: S3 Bucket S3BucketPolicyAccountAccess policy has non-allowed principals 666555444333
	- S3BucketPolicyPrincipalRule: S3 Bucket S3BucketPolicyAccountAccess policy has non-allowed principals 123456789012
	- S3BucketPolicyPrincipalRule: S3 Bucket S3BucketPolicyAccountAccess policy has non-allowed principals 666555444333
	- S3BucketPublicReadAclAndListStatementRule: S3 Bucket S3BucketPolicyAccountAccess should not have a public read acl and list bucket statement
```

With `--aws-account-id` argument, 6 issues:
```bash
$ cfripper ./tests/test_templates/rules/S3CrossAccountTrustRule/s3_bucket_cross_account_and_normal.json --format txt --aws-account-id 123456789012 --resolve
Analysing ./tests/test_templates/rules/S3CrossAccountTrustRule/s3_bucket_cross_account_and_normal.json...
Using `UNDEFINED_PARAM_S3Bucket` for S3Bucket. Original value wasn't available.
Valid: False
Issues found:
	- PartialWildcardPrincipalRule: S3BucketPolicyAccountAccess should not allow wildcard, account-wide or root in resource-id like 'arn:aws:iam::12345:root' at 'arn:aws:iam::123456789012:role/some-role/some-other-sub-role'
	- PartialWildcardPrincipalRule: S3BucketPolicyAccountAccess should not allow wildcard, account-wide or root in resource-id like 'arn:aws:iam::12345:root' at 'arn:aws:iam::666555444333:root'
	- S3BucketPolicyPrincipalRule: S3 Bucket S3BucketPolicyAccountAccess policy has non-allowed principals 666555444333
	- S3BucketPolicyPrincipalRule: S3 Bucket S3BucketPolicyAccountAccess policy has non-allowed principals 666555444333
	- S3BucketPublicReadAclAndListStatementRule: S3 Bucket S3BucketPolicyAccountAccess should not have a public read acl and list bucket statement
	- S3CrossAccountTrustRule: S3BucketPolicyAccountAccess has forbidden cross-account policy allow with arn:aws:iam::666555444333:root for an S3 bucket.
```

With both arguments, 4 issues:
```bash
$ cfripper ./tests/test_templates/rules/S3CrossAccountTrustRule/s3_bucket_cross_account_and_normal.json --format txt --aws-account-id 123456789012 --aws-principals 666555444333 --resolve
Analysing ./tests/test_templates/rules/S3CrossAccountTrustRule/s3_bucket_cross_account_and_normal.json...
Using `UNDEFINED_PARAM_S3Bucket` for S3Bucket. Original value wasn't available.
Valid: False
Issues found:
	- PartialWildcardPrincipalRule: S3BucketPolicyAccountAccess should not allow wildcard, account-wide or root in resource-id like 'arn:aws:iam::12345:root' at 'arn:aws:iam::123456789012:role/some-role/some-other-sub-role'
	- PartialWildcardPrincipalRule: S3BucketPolicyAccountAccess should not allow wildcard, account-wide or root in resource-id like 'arn:aws:iam::12345:root' at 'arn:aws:iam::666555444333:root'
	- S3BucketPublicReadAclAndListStatementRule: S3 Bucket S3BucketPolicyAccountAccess should not have a public read acl and list bucket statement
	- S3CrossAccountTrustRule: S3BucketPolicyAccountAccess has forbidden cross-account policy allow with arn:aws:iam::666555444333:root for an S3 bucket.
```