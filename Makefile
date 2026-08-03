SOURCES = cfripper tests docs

install:
	uv sync --no-dev --locked

install-dev:
	uv sync --group dev --locked

install-docs:
	uv sync --group docs --locked

format:
	uv run --locked ruff format $(SOURCES)
	uv run --locked ruff check --fix $(SOURCES)

lint:
	uv run --locked ruff check $(SOURCES)

unit:
	uv run --locked pytest -svvv tests

coverage:
	uv run --locked pytest --cov cfripper

test: lint unit

test-docs:
	uv run --locked mkdocs build --strict

lock:
	uv lock

lock-upgrade:
	uv lock --upgrade

build:
	uv build

check-package:
	uv run --locked twine check --strict dist/*

.PHONY: install install-dev install-docs format lint unit coverage test test-docs lock lock-upgrade build check-package
