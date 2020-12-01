# Changelog
All notable changes to this project will be documented in this file.

## [0.21.0] - 2020-11-30
### Improvements
- Upgraded to pycfmodel 0.8.1 (this will improve policy action detection)
- Refactored a few classes to use improvements from new base classes and pycfmodel
- `PrivilegeEscalationRule` now detects issues in all policies
### Additions
- New Rules: `SNSTopicDangerousPolicyActionsRule` and `SQSDangerousPolicyActionsRule`
- New abstract base rule: BaseDangerousPolicyActions
### Fixes
- Various typo fixes

## [0.20.1] - 2020-10-26
### Improvements
- Added more actions that only allow wildcard as resource
### Fixes
- Require pycfmodel 0.7.2
### Other
- Bump pip-tools dev requirement to 5.3.1

## [0.20.0] - 2020-09-30
### Improvements
- Add `WildcardResourceRule` rule

## [0.19.2] - 2020-09-16
### Improvements
- Add `regex:ignorecase` filter function

## [0.19.1] - 2020-09-01
### Improvements
- Add support for this new S3 url format: `https://bucket.s3.aws-region.amazonaws.com/path1/path2`

## [0.19.0] - 2020-05-21
### Breaking changes
- `rule_mode` is now `BLOCKING` for all Rules.

## [0.18.1] - 2020-04-14
### Fixed
- `CrossAccountCheckingRule` calling `add_failure_to_result` on `UNDEFINED_` was missing context variable.

## [0.18.0] - 2020-04-07
### Improvements
- `EC2SecurityGroupIngressOpenToWorldRule`, `EC2SecurityGroupMissingEgressRule` and `EC2SecurityGroupOpenToWorldRule` include support for filters.
- `EC2SecurityGroupIngressOpenToWorldRule` and `EC2SecurityGroupOpenToWorldRule` support adding errors for port ranges.
### Breaking changes
- `Config.DEFAULT_ALLOWED_WORLD_OPEN_PORTS` type changes to `List[int]`
- Rename `SecurityGroupIngressOpenToWorldRule` to `EC2SecurityGroupIngressOpenToWorldRule`
- Rename `SecurityGroupMissingEgressRule` to `EC2SecurityGroupMissingEgressRule`
- Rename `SecurityGroupOpenToWorldRule` to `EC2SecurityGroupOpenToWorldRule`
- Improved message for users when failing the `SecurityGroupOpenToWorldRule` and `SecurityGroupIngressOpenToWorldRule` rules.
- Improved documentation for the above rules, including styling fixes which have now been tested.

## [0.17.2] - 2020-04-01
### Improvements
- Improved message for users when failing the `SecurityGroupOpenToWorldRule` and `SecurityGroupIngressOpenToWorldRule` rules.
- Improved documentation for the above rules, including styling fixes which have now been tested.

## [0.17.1] - 2020-03-30
### Improvements
- Add `exists` and `empty` functions to filters
- Add `param_resolver` to filters to evaluate just necessary params
### Fixed
- Add protection when a filter is evaluated to catch the exception and continue

## [0.17.0] - 2020-03-27
### Improvements
- `CrossAccountCheckingRule`, `CrossAccountTrustRule`, `S3CrossAccountTrustRule` and `KMSKeyCrossAccountTrustRule` include support for filters.
### Breaking changes
- `CrossAccountCheckingRule` now includes the invoke method. Statements of PolicyDocument are now analysed using `RESOURCE_TYPE` and `PROPERTY_WITH_POLICYDOCUMENT` class variables. 

## [0.16.0] - 2020-03-27
### Improvements
- Add new `RuleConfig`, allows to overwrite the default behaviour of the rule changing rule mode and risk value.
- Add new `Filter`, allows setting custom rule configuration to matching coincidences.
- New RuleModes supported: `RuleMode.DISABLED` and `RuleMode.WHITELISTED`.
### Breaking changes
- Class variables `Rule.RULE_MODE` and `Rule.RISK_VALUE` should be changed to use properties `rule_mode` and `risk_value`. These properties take in consideration the custom config that might be applied.
- If rule mode is `DISABLED` or `WHITELISTED`; methods `add_failure_to_result` and `add_warning_to_result` will have no effect.
- `add_failure_to_result` and `add_warning_to_result` accepts a new optional parameter named `context`. This variable is going to be evaluated by filters defined in the custom config.

## [0.15.1] - 2020-03-26
### Improvements
- `SecurityGroupOpenToWorldRule` and `SecurityGroupIngressOpenToWorldRule` are now more accurately scoped to block
potentially public CIDR ranges. It it utilising the latest `pycfmodel` release (0.7.0).

## [0.15.0] - 2020-03-25
### Improvements
- Generate DEFAULT_RULES and BASE_CLASSES using code instead of hardcoding
### Fixed
- Whitelist did not work if it didn't have the `Rule` prefix
### Breaking changes
- Sufix `KMSKeyWildcardPrincipal` and `SecurityGroupIngressOpenToWorld` with `Rule`
- Sufix whitelist constant `FullWildcardPrincipal` and `PartialWildcardPrincipal` with `Rule`

## [0.14.2] - 2020-03-04
### Improvements
- Update dependencies

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
