SOURCES = cfripper tests docs

PIP_COMMAND = pip
install:
	$(PIP_COMMAND) install -r requirements.txt

install-dev:
	$(PIP_COMMAND) install -r requirements.txt -r requirements-dev.txt .

install-docs:
	$(PIP_COMMAND) install -r requirements.txt -r requirements-docs.txt .

format:
	ruff format $(SOURCES)

lint:
	ruff check $(SOURCES)

unit:
	pytest -svvv tests

coverage:
	pytest --cov cfripper

test: lint unit

test-docs:
	mkdocs build --strict

FREEZE_COMMAND = CUSTOM_COMPILE_COMMAND="make freeze" uv pip compile
FREEZE_OPTIONS = --no-emit-index-url --no-annotate -v
freeze-base: pyproject.toml
	$(FREEZE_COMMAND) $(FREEZE_OPTIONS) pyproject.toml --output-file requirements.txt
freeze-dev: pyproject.toml
	$(FREEZE_COMMAND) $(FREEZE_OPTIONS) pyproject.toml --extra dev --output-file requirements-dev.txt
freeze-docs: pyproject.toml
	$(FREEZE_COMMAND) $(FREEZE_OPTIONS) pyproject.toml --extra dev --extra docs --output-file requirements-docs.txt
freeze: freeze-base freeze-dev freeze-docs

freeze-upgrade-base:
	$(FREEZE_COMMAND) $(FREEZE_OPTIONS) pyproject.toml --upgrade --output-file requirements.txt
freeze-upgrade-dev:
	$(FREEZE_COMMAND) $(FREEZE_OPTIONS) pyproject.toml --upgrade --extra dev --output-file requirements-dev.txt
freeze-upgrade-docs:
	$(FREEZE_COMMAND) $(FREEZE_OPTIONS) pyproject.toml --upgrade --extra docs --extra dev --output-file requirements-docs.txt
freeze-upgrade: freeze-upgrade-base freeze-upgrade-dev freeze-upgrade-docs


.PHONY: install install-dev install-docs format lint unit coverage test freeze freeze-upgrade\
	freeze-base freeze-dev freeze-docs freeze-upgrade-base freeze-upgrade-dev freeze-upgrade-docs
