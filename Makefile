SOURCES = cfripper tests docs

install:
	uv sync --no-dev --frozen

install-dev:
	uv sync --frozen

install-docs:
	uv sync --group docs --frozen

format:
	uv run --frozen ruff format $(SOURCES)
	uv run --frozen ruff check --fix $(SOURCES)

lint:
	uv run --frozen ruff check $(SOURCES)

unit:
	uv run --frozen pytest -svvv tests

coverage:
	uv run --frozen pytest --cov cfripper

test: lint unit

test-docs:
	uv run --frozen mkdocs build --strict

lock:
	uv lock

lock-upgrade:
	uv lock --upgrade

build:
	uv build

check-package:
	uv run --frozen twine check --strict dist/*

.PHONY: install install-dev install-docs format lint unit coverage test test-docs lock lock-upgrade build check-package
