# Changelog
All notable changes to this project will be documented in this file.

## [0.14.1] - 2020-02-24
### Improvements
- Rule processor now accepts an extras parameter that will be forwarded to the rules
- Main gets extra information from the event and forwards it to the rule formatter

## [0.14.0] - 2020-02-07
### Breaking changes
- Completely changed base `Rule` abstract class signature and adapted rule classes to match it:
    - Init now only takes a `Config`
    - `invoke` method now accepts an optional extra Dict
    - `invoke` method returns a `Result` instead of `None` 
    - `add_failure` has been renamed to `add_failure_to_result`. It now takes a result instead of a reason 
    (that now it's inferred)
    - `add_warning` has been renamed to `add_warning_to_result`. It now has the same signature than `add_failure_to_result`
### Improvements
- Rule Invoke extras parameter has been added to allow changing the rule behaviour depending on state besides the cfmodel itself:
    - Stack naming rules
    - Stack tags
    - User restrictions
    - ...

## [0.13.0] - 2020-01-22
### Fixed
- Regular expressions had an unescaped '.' before 'amazonaws.com', so it might match more hosts than expected.
### Changed
- `CloudFormationAuthenticationRule` now in `MONITOR` mode and new test added
- `IAMRoleWildcardActionOnPolicyRule` combines three previous unused rules in `IAMManagedPolicyWildcardActionRule`, `IAMRoleWildcardActionOnPermissionsPolicyRule`, and `IAMRoleWildcardActionOnTrustPolicyRule`
- `IAMRoleWildcardActionOnPolicyRule` now in `DEBUG` mode
- `S3BucketPolicyWildcardActionRule` has now been changed to be an instantiation of the new generic rule `GenericWildcardPolicyRule`. It is set in `DEBUG` mode
- `S3BucketPolicyWildcardActionRule` has had updated regex filter to make it more aligned with both further rules to do with wildcards in actions, and the existing `SQSQueuePolicyWildcardActionRule`
- `SQSQueuePolicyWildcardActionRule` has now been changed to be an instantiation of the new generic rule `GenericWildcardPolicyRule`. It is set in `DEBUG` mode
- `SecurityGroupMissingEgressRule` now in `DEBUG` mode and a new test added
- `SNSTopicPolicyWildcardActionRule` has beed added. It is an instantiation of the new generic rule `GenericWildcardPolicyRule`. It is set in `DEBUG` mode
### Breaking changes
- The following rules are no longer available:
  - `IAMRoleWildcardActionOnPermissionsPolicyRule`
  - `IAMRoleWildcardActionOnTrustPolicyRule`
  - `IAMManagedPolicyWildcardActionRule`
- The following rules have been moved:
  - `S3BucketPolicyWildcardActionRule`
  - `SQSQueuePolicyWildcardActionRule`

## [0.12.2] - 2020-01-13
### Improvements
- Documentation updated to show the risk of rules and possible fixes where available, 
as well as a large set of updates to the content. The macros for parsing the documentation
have also been updated.

## [0.12.1] - 2020-01-09
### Fixes
- Fix for `CrossAccountCheckingRule` was adding errors when the principal was sts when it shouldn't. 
### Added
- `get_account_id_from_sts_arn` and `get_aws_service_from_arn` in utils.

## [0.12.0] - 2020-01-08
### Added
- Adds CLI to package
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
