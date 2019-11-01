# Changelog
All notable changes to this project will be documented in this file.

## [Unreleased]

## [0.10.0] - 2019-11-XX
### Added
- New regex `REGEX_IS_STAR`, matches only a `*` character.

### Changed
- `GenericWildcardPrincipalRule` now trust the condition to reduce false positives.
- Rules check the resource type using `isinstance` instead of comparing type to a string if pycfmodel implements the resource. 

### Fixed
- `IAMRolesOverprivilegedRule` now uses `REGEX_IS_STAR` for finding statements instead of `REGEX_CONTAINS_STAR`.
