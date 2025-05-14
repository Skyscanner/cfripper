# Changelog
All notable changes to this project will be documented in this file.

## [1.17.2]
### Updates
- Truncate metric arguments to 4000 characters

## [1.17.1]
### Updates
- Solve low-severity warnings for better readability
- Add support for repo_name in config

## [1.17.0]
### Additions
- Add support for python 3.13
- Add RequestCertificate to wildcard whitelist @undergroundwires (#308)
### Removals
- Remove support for python 3.8

## [1.16.0]
### Additions
- Added 2 new filter functions: `set` and `sorted`

## [1.15.7]
### Updates
- Bumped pycfmodel to use pydantic v2
### Other updates
- Add PR template @w0rmr1d3r (#279)

## [1.15.6]
### Fixes
- Fix logo in pypi @ignaciobolonio (#274)
### Updates
- Update .readthedocs.yaml @jsoucheiron (#275)
### Bumps
- Bump actions/setup-python from 4 to 5 (#270)
- Bump cryptography from 42.0.3 to 42.0.4 (#272)

## [1.15.5]
### Changes
- Migrate to pyproject.toml @jsoucheiron (#269)
- Add dependabot config @w0rmr1d3r (#257)

## [1.15.4]
### Fixes
- Fix `KMSKeyWildcardPrincipalRule` to work without a KMS policy
- Fix release drafter template to show PR titles
### Updates
- Bumped minimum `pycfmodel` version to `0.22.0`

## [1.15.3]
### Changes
- Update invalid_role_inline_policy_fn_if.json 
- Improve logging for the exception when applying rule filters
- Add release drafter 

## [1.15.2]
### Fixes
- Fixes https://github.com/Skyscanner/cfripper/issues/260

## [1.15.1]
### Fixes
- Fix docs generation

## [1.15.0]
### Additions
- New rules: `PublicELBCheckerRule`, `StackNameMatchesRegexRule`, and `StorageEncryptedRule`
- New regex: `REGEX_ALPHANUMERICAL_OR_HYPHEN` to check if stack name only consists of alphanumerical characters and hyphens.
- Config has a few extra methods that should make handling Filters easier

## [1.14.0]
### Additions
- `Config` includes a metrics logger, and it is called to register when a filter is used
### Fixes
- Update dependency constraints with `pydash`, to be able to support newer versions and fix security issues
- Fix typo in base_rule actions [#237](https://github.com/Skyscanner/cfripper/pull/237)
- (internal) Updating PyPi release workflow

## [1.13.2]
### Fixes
- Fixes docs formatting with [#235](https://github.com/Skyscanner/cfripper/pull/235)

## [1.13.1]
### Fixes
- Fixes `GenericResourcePartialWildcardPrincipalRule` and `GenericCrossAccountTrustRule` message, since sometimes it was bad-formatted in markdown.

## [1.13.0]
### Additions
- Default logging level from INFO to WARNING #230
### Updates
- `GenericResourceWildcardPrincipalRule` (therefore `GenericResourcePartialWildcardPrincipalRule` and `GenericResourceFullWildcardPrincipalRule` as well) now ignores `AWS::KMS::ReplicaKey`. It as the same use case as a `AWS::KMS::Key`.
### Fixes
- Update `GenericWildcardPrincipalRule`, `FullWildcardPrincipalRule`, `GenericResourceWildcardPrincipalRule` and `GenericResourceFullWildcardPrincipalRule` message, since sometimes it was bad-formatted in markdown.

## [1.12.0]
### Improvements
- Refactored the `KMSKeyWildcardPrincipalRule` rule
### Updates
- Update `GenericWildcardPrincipalRule`, `PartialWildcardPrincipalRule` and `GenericResourcePartialWildcardPrincipalRule` message
- Update docs
### Fixes
- Fix `GenericWildcardPrincipalRule` that could add a false-positive
- Fix `GenericWildcardPrincipalRule` that wasn't handling canonical IDs
- Fix `REGEX_PARTIAL_WILDCARD_PRINCIPAL` to correctly handle canonical IDs and account IDs
- Fix unit tests

## [1.11.0]
### Additions
- New regex `REGEX_CONTAINS_WILDCARD` to check for any wildcard
### Updates
- `GenericResourceWildcardPolicyRule` now uses `REGEX_CONTAINS_WILDCARD` instead of `REGEX_HAS_STAR_OR_STAR_AFTER_COLON`.
- Bump dev dependency `moto` to `==3.1.9`.

## [1.10.0]
### Improvements
- `GenericCrossAccountTrustRule` can now scan IAM Roles correctly as `CrossAccountTrustRule` does
### Additions
- New rule: `RDSSecurityGroupIngressOpenToWorldRule`
### Updates
- Bumped minimum `pycfmodel` version to `0.20.0`

## [1.9.0]
### Improvements
- CFRipper is now compatible with Python3.10
- CFRipper is now able to detect new types of wildcard usage.
- Default config will now detect lambda resource wildcards as through IAM overpowered roles.

### Updates
- Bump dev dependency `moto` to allow `>=3.0.0`.

## [1.8.0]
### Improvements
- Pin `click` to at least version `8.0.0`.
- Update `black` to `22.3.0`, and run `make format` with this new version of `black`.

## [1.7.1]
### Fixes
- `EBSVolumeHasSSERule` can now understand `encrypted_status` if modelled as a `bool`.
- Add support to `EC2SecurityGroupOpenToWorldRule` for use cases where ports are not defined in the CloudFormation template. By default, this means all ports are included.
### Updates
- Updated `EBSVolumeHasSSERule` to iterate only over `AWS::EC2::Volume` resources.
- Update `RuleConfig` documentation.
### Improvements
- Bump `pycfmodel` to `0.18.0`.

## [1.7.0]
### Updates
- Added `resource_types` to failures.

## [1.6.0]
### Updates
- Created `GenericResourceWildcardPrincipalRule` to be an abstract for wildcard principals for Generic resources.
- Created `GenericResourcePartialWildcardPrincipalRule` and `GenericResourceFullWildcardPrincipalRule` to evaluate Generic resources.
### Fixes
- Rollback `GenericWildcardPrincipalRule` as it was in `1.5.2`.

## [1.5.3]
### Updates
- Updates `GenericWildcardPrincipalRule` to understand the `GenericResource`.
### Fixes
- Stopped using `_statement_as_list()` when retrieving statements in favor of `statement_as_list()`.

## [1.5.2]
### Updates
- Updates `WildcardResourceRule` for a better use with the `GenericResource`.
### Fixes
- Stopped using `_statement_as_list()` when retrieving statements in several rules in favor of `statement_as_list()`.

## [1.5.1]
### Updates
- Created `GenericResourceWildcardPolicyRule` in order to check for WildcardPolicy issues in generic resources.
- Added documentation regarding the deprecation of `S3BucketPolicyWildcardActionRule`, `SNSTopicPolicyWildcardActionRule` and `SQSQueuePolicyWildcardActionRule`.
- Covering cases for already mapped models in rules inherited from `GenericWildcardPolicyRule` with the new `GenericResourceWildcardPolicyRule`.

## [1.5.0]
### Updates
- Created `GenericCrossAccountTrustRule` in order to check for CrossAccount issues for generic resources.
- Added documentation regarding the deprecation of `S3CrossAccountTrustRule`, `KMSKeyCrossAccountTrustRule`, `ElasticsearchDomainCrossAccountTrustRule` and `OpenSearchDomainCrossAccountTrustRule`.
- Covering cases for already mapped models in rules inherited from `CrossAccountCheckingRule` with the new `GenericCrossAccountTrustRule`.
### Improvements
- Bump `pycfmodel` to `0.17.0`
### Fixes
- Stopped using `_statement_as_list()` when retrieving statements in `CrossAccountCheckingRule` in favor of `statement_as_list()`.

## [1.4.2] - 2022-2-28
### Fixes
- Fix how `make install-dev` works, it will install dependencies from `make install` first.
### Improvements
- Bump dev dependency `moto` from `1.3.13` to `1.3.14`.

## [1.4.1] - 2022-2-24
### Improvements
- Bump `pycfmodel` to `0.16.3`

## [1.4.0] - 2022-2-21
### Fixes
- Fix CI, updated tests to work with `pycfmodel` latest version which includes the use of the `Generic`.
### Improvements
- Bump and fixed required dependency `pycfmodel` to be at least `0.16.2`.
- Bump several dependencies: 
  - `boto3` to `1.21.2`
  - `botocore` to `1.24.2`
  - `cfn-flip` to `1.3.0`
  - `pydantic` to `1.9.0`
  - `python-dateutil` to `2.8.2`
  - `pyyaml` to `6.0`
  - `s3transfer` to `0.5.1`
  - `typing-extensions` to `4.1.1`
  - `urllib3` to `1.26.8`

## [1.3.3] - 2022-2-3
### Fixes
- Fix CI, force `pycfmodel` to use version `0.13.0`.

## [1.3.2] - 2022-2-3
### Updates
- Stop logging when conditions are ignored in `CrossAccountCheckingRule`, `KMSKeyWildcardPrincipalRule`, `S3BucketPolicyPrincipalRule`, `SQSQueuePolicyPublicRule` and `GenericWildcardPrincipalRule`.

## [1.3.1] - 2022-1-17
### Fixes
- Fixes `CrossAccountCheckingRule` when checking resources without `PROPERTY_WITH_POLICYDOCUMENT`.

## [1.3.0] - 2022-1-17
### Improvements
- Add `ElasticsearchDomainCrossAccountTrustRule` and `OpenSearchDomainCrossAccountTrustRule`
- Bump `pycfmodel` to `0.13.0`

## [1.2.2] - 2022-1-07
### Improvements
- Bump `pycfmodel` to `0.11.1`

## [1.2.1] - 2021-12-24
### Fixes
- The `WildcardResourceRule` would fail if it received a policy document that was a string. It was expecting all policy documents to be a dictionary. Some AWS services allow for string policies though (e.g. `AWS::Logs::ResourcePolicy`). The rule has been updated to handle string policies by attempting to convert it to a dictionary.

## [1.2.0] - 2021-11-03
### Updates
- The rules `EC2SecurityGroupOpenToWorldRule` and `EC2SecurityGroupIngressOpenToWorldRule` were by default allowing ports 80 and 443. This has now been migrated to use a filter object, that can be optionally applied. See the README for further details. This means if the filter is not applied, Security Groups open to the world on ports 80 and 443 will start failing in CFRipper.

## [1.1.2] - 2021-10-06
### Fixes
- Add a fix to the `KMSKeyEnabledKeyRotation` rule to be able to detect the `EnableKeyRotation` property properly.

## [1.1.1] - 2021-09-30
### Fixes
- Add a fix to the `PartialWildcardPrincipal` rule to be able to detect policies where whole account access is specified via just the account ID.
- For example, if the Principal was defined as `Principal: AWS: 123456789012` as opposed to `Principal: AWS: arn:aws:iam::123456789012:root`.
  - These are identical: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html

## [1.1.0] - 2021-09-22
### Improvements
- Add `S3ObjectVersioning` rule
- Update `pycfmodel` to `0.11.0`
  - This includes model support for S3 Buckets. Rules against these resources have been updated (alongside tests).

## [1.0.9] - 2021-09-10
### Improvements
- Update valid AWS Account IDs that might be included as principals on policies.
- This list now covers ELB Logs, CloudTrail Logs, Redshift Audit, and ElastiCache backups.
- `WildCardResourceRule` is now triggered by resources that only limit by service (ex: `arn:aws:s3:::*`)

## [1.0.8] - 2021-08-18
### Improvements
- Add `S3LifecycleConfiguraton` rule

## [1.0.7] - 2021-08-16
### Improvements
- Add `KMSKeyEnabledKeyRotation` rule
- Bump `pycfmodel` to `0.10.4`

## [1.0.6] - 2021-07-28
### Improvements
- Add `S3BucketPublicReadAclRule` rule

## [1.0.5] - 2021-07-28
### Improvements
- Add EKS permissions that accept wildcard resource only

## [1.0.4] - 2021-06-03
### Improvements
- Add `stack_id` to log output when failing to convert a YML template to JSON.
- Various minor test improvements
- Added CLI args for aws account id and aws principals
- Fix an issue in `S3BucketPublicReadAclAndListStatementRule` where it could crash if the model was unresolved
- Center logo (thanks @lpmi-13)
- Run tests in python 3.9 

## [1.0.3] - 2021-03-26
### Improvements
- Downgrade logging severity from exception to warning when there is no stack in AWS

## [1.0.2] - 2021-03-25
### Improvements
- Handle AWS throttling errors when listing exports for a given account and region
- If we get a throttling error, we actually sleep for some time before retrying (before we were sleeping for 0 seconds)

## [1.0.1] - 2021-03-25
### Improvements
- Decrease logging level when loading external filters
- Decrease logging level on known AWS errors such as AccessDenied when listing exports and
throttling errors on getting a template from AWS CloudFormation.

## [1.0.0] - 2021-03-16
### Breaking changes
- `Filter` include the set of rules in which it is applied.
- `RuleConfig` only contains `rule_mode` and `risk_value` now.
- Removes old whitelisting methods in favour of Filters
- Rename `RuleMode.WHITELISTED` to `RuleMode.ALLOWED`, and all `whitelist` word in strings.
- Add debug flag to `Filter` class.
### Improvements
- Implements `pluggy` https://github.com/pytest-dev/pluggy to enable dynamic rule loading.
- Add support to load filters from external files

## [0.23.3] - 2021-02-11
### Additions
- All rules now support filter contexts!
### Improvements
- Update `WildcardResourceRule` to allow for certain resources to be excluded.

## [0.23.2] - 2021-02-04
### Bugfix
- `GenericWildcardPrincipalRule` to ignore account IDs where full or partial wildcard is required in the Principal.
These accounts should be AWS Service Accounts defined in the config.
- Fix CLI flag `--rules-config-file`
### Improvements
- Update `ResourceSpecificRule` to allow for certain resources to be excluded. In particular, the
`PrivilegeEscalationRule` will now no longer be invoked for `S3BucketPolicy` resources.
- Add rules config for Kinesis Data Firehose IPs that can be applied

## [0.23.1] - 2021-01-26
### Improvements
- Add more X-Ray permissions that accept wildcard resource only
- CLI handles case of empty template by returning appropriate exception message
- CLI now returns exit code 2 for scenarios where CFRipper finds a template violating any of the rules

## [0.23.0] - 2021-01-20
### Breaking changes
- Rule config files using filters must now use `ingress_obj` and not `ingress`.
### Additions
- Rules using IP Address Ranges now export both `ingress_obj` and `ingress_ip` filter fields.
- Add support to load an external rules configuration file

## [0.22.0] - 2020-12-11
### Breaking changes
- Classes inheriting from `ResourceSpecificRule` now must allow an `extra` field in the `resource_invoke` function
### Improvements
- Improved context data for `BaseDangerousPolicyActions` and classes inheriting from it
### Bugfix
- `CrossAccountCheckingRule` did not check properly for calculated mock fields. 

## [0.21.1] - 2020-12-9
### Improvements
- Add SNS actions that only allow wildcards

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
