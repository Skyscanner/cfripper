# Changelog
All notable changes to this project will be documented in this file.

## [0.10.2] - 2019-11-20
### Added
- Added `PrincipalCheckingRule`, it has a property called `valid_principals`. It's a list with all allowed principals. 
### Changed
- `CrossAccountTrustRule` outputs warning log message if the AWS Account ID is not present in the config.
- `HardcodedRDSPasswordRule` updated to check for both RDS Clusters and RDS Instances, and reduce false positives on valid instances.
- `CrossAccountTrustRule`, `GenericWildcardPrincipalRule`, `S3BucketPolicyPrincipalRule`, `S3BucketPolicyPrincipalRule` and `S3CrossAccountTrustRule` now check the account against a list.
  The list is composed of AWS service accounts, configured AWS principals and the account id where the event came from.

## [0.10.1] - 2019-11-14
### Added
- New regexes and utility methods to get parts of arns
### Changed
- `S3CrossAccountTrustRule` and `S3BucketPolicyPrincipalRule` won't trigger if the principal comes from one of the AWS ELB service account ids

## [0.10.0] - 2019-11-08
### Added
- New regex `REGEX_IS_STAR`, matches only a `*` character.

### Changed
- `GenericWildcardPrincipalRule`, `S3BucketPolicyPrincipalRule`, `S3CrossAccountTrustRule`, `SQSQueuePolicyPublicRule` and `KMSKeyWildcardPrincipal` now trust the condition to reduce false positives.
- Rules check the resource type using `isinstance` instead of comparing type to a string if pycfmodel implements the resource. 
- Instance method `add_failure` now accepts `risk_value` and `risk_mode` as optional parameters. 
- `CrossAccountTrustRule` only runs if config has defined `self._config.aws_account_id`.
- `IAMRoleWildcardActionOnPermissionsPolicyRule`now uses `REGEX_WILDCARD_POLICY_ACTION`.

### Fixed
- `IAMRolesOverprivilegedRule` now uses `REGEX_IS_STAR` for finding statements instead of `REGEX_CONTAINS_STAR`.
