# Changelog
All notable changes to this project will be documented in this file.

## [0.12.0] - 2019-12-17
### Added
- `KMSKeyCrossAccountTrustRule`
### Changed
- `GenericWildcardPrincipalRule`, `PartialWildcardPrincipalRule`, `FullWildcardPrincipalRule` no longer check for
wildcards in KMSKey principals.
- Improved granularity of most rules 

## [0.11.3] - 2019-12-17
### Improvements
- `S3CrossAccountTrustRule` now accepts resource level exceptions
- New documentation!
### Breaking changes
- `cfripper.rules.s3_bucked_policy` renamed to `cfripper.rules.s3_bucket_policy` (typo)

## [0.11.2] - 2019-11-26
### Fixes
- Fix `get_template` when AWS doesn't return a dict.

## [0.11.1] - 2019-11-25
### Changed
- `HardcodedRDSPasswordRule` now reports two different messages when there is a missing echo or a readable password.
### Fixes
- `HardcodedRDSPasswordRule` was wrongly adding an error when a value is provided.

## [0.11.0] - 2019-11-20
### Breaking changes
- Moved some files from model to rules, renamed rules to match pythonic style. Moved tons of classes around
### Fixes
- Fix a regression that caused `S3CrossAccountTrustRule` and `CrossAccountTrustRule` not to alert whenever 
cross-account permissions are found within the allowed list of aws accounts.
- `CrossAccountTrustRule` wrongly say that AWS canonical ids and services were a cross-account relationship.

## [0.10.2] - 2019-11-20
### Added
- Added `PrincipalCheckingRule`, it has a property called `valid_principals`. It's a list with all allowed principals. 
This list can be customized using `_get_whitelist_from_config()`.
- Added `AWS_ELASTICACHE_BACKUP_CANONICAL_IDS` which contains the aws canonical ids used for backups.
### Changed
- `CrossAccountTrustRule` outputs warning log message if the AWS Account ID is not present in the config.
- `HardcodedRDSPasswordRule` updated to check for both RDS Clusters and RDS Instances, and reduce false positives on 
valid instances.
- `CrossAccountTrustRule`, `GenericWildcardPrincipalRule`, `S3BucketPolicyPrincipalRule`, `S3BucketPolicyPrincipalRule` 
and `S3CrossAccountTrustRule` now check the account against a list.
  The list is composed of AWS service accounts, configured AWS principals and the account id where the event came from.
- Rename `AWS_ELB_ACCOUNT_IDS` to `AWS_ELB_LOGS_ACCOUNT_IDS`

## [0.10.1] - 2019-11-14
### Added
- New regexes and utility methods to get parts of arns
### Changed
- `S3CrossAccountTrustRule` and `S3BucketPolicyPrincipalRule` won't trigger if the principal comes from one of the AWS 
ELB service account ids

## [0.10.0] - 2019-11-08
### Added
- New regex `REGEX_IS_STAR`, matches only a `*` character.

### Changed
- `GenericWildcardPrincipalRule`, `S3BucketPolicyPrincipalRule`, `S3CrossAccountTrustRule`, `SQSQueuePolicyPublicRule` 
and `KMSKeyWildcardPrincipal` now trust the condition to reduce false positives.
- Rules check the resource type using `isinstance` instead of comparing type to a string if pycfmodel implements the 
resource. 
- Instance method `add_failure` now accepts `risk_value` and `risk_mode` as optional parameters. 
- `CrossAccountTrustRule` only runs if config has defined `self._config.aws_account_id`.
- `IAMRoleWildcardActionOnPermissionsPolicyRule`now uses `REGEX_WILDCARD_POLICY_ACTION`.

### Fixed
- `IAMRolesOverprivilegedRule` now uses `REGEX_IS_STAR` for finding statements instead of `REGEX_CONTAINS_STAR`.
