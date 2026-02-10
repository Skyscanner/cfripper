# CFRipper

CFRipper is a library and CLI security analyzer for AWS CloudFormation templates.

## Build & Test Commands

- `make install-dev` - Install development dependencies
- `make install-docs` - Install docs dependencies
- `make test` - Run lint + unit tests
- `make unit` - Run unit tests only (`uv run --frozen pytest -svvv tests`)
- `make lint` - Run ruff linter
- `make format` - Format code with ruff
- `make coverage` - Run tests with coverage
- `make test-docs` - Build docs with strict mode
- `make lock` - Update uv.lock after dependency changes
- `make lock-upgrade` - Update all dependencies to latest versions
- `make build` - Build the package

## Project Structure

- `cfripper/` - Main package (rules, config, CLI)
- `tests/` - Test suite
- `docs/` - MkDocs documentation source
- `pyproject.toml` - Project metadata and dependencies
- `uv.lock` - Locked dependencies (managed by uv)
- `Makefile` - All dev commands use `uv run --frozen`

## Dependencies

- Managed with [uv](https://docs.astral.sh/uv/)
- Dev dependencies in `[dependency-groups] dev`
- Docs dependencies in `[dependency-groups] docs`
- Always run `make lock` after modifying dependencies in `pyproject.toml`

## Code Style

- Linter/formatter: ruff
- Line length: 120
- Target: Python 3.10+
- Double quotes, space indentation
