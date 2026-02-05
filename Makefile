SOURCES = cfripper tests docs

install:
	uv sync --no-dev

install-dev:
	uv sync --all-extras

install-docs:
	uv sync --extra docs

format:
	ruff format $(SOURCES)
	ruff check --fix $(SOURCES)

lint:
	ruff check $(SOURCES)

unit:
	pytest -svvv tests

coverage:
	pytest --cov cfripper

test: lint unit

test-docs:
	mkdocs build --strict

lock:
	uv lock

lock-upgrade:
	uv lock --upgrade

.PHONY: install install-dev install-docs format lint unit coverage test test-docs lock lock-upgrade
