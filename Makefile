SOURCE_DIRS = cfripper tests docs
SOURCE_FILES = setup.py
SOURCE_ALL = $(SOURCE_DIRS) $(SOURCE_FILES)

install:
	uv pip install -r requirements.txt

install-dev: install
	uv pip install -r requirements.txt -r requirements-dev.txt

install-docs:
	uv pip install -r requirements.txt -r requirements-docs.txt

format:
	isort --recursive $(SOURCE_ALL)
	black $(SOURCE_ALL)

lint: isort-lint black-lint flake8-lint

isort-lint:
	isort --check-only --recursive $(SOURCE_ALL)

black-lint:
	black --check $(SOURCE_ALL)

flake8-lint:
	flake8 $(SOURCE_ALL)

unit:
	pytest -svvv tests

coverage:
	coverage run --source=cfripper --branch -m pytest tests/ --junitxml=build/test.xml -v
	coverage report
	coverage xml -i -o build/coverage.xml
	coverage html

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
	$(FREEZE_COMMAND) pyproject.toml --upgrade --extra dev --output-file requirements-dev.txt
freeze-upgrade-docs:
	$(FREEZE_COMMAND) pyproject.toml --upgrade --extra docs --extra dev --output-file requirements-docs.txt
freeze-upgrade: freeze-upgrade-base freeze-upgrade-dev freeze-upgrade-docs


.PHONY: install install-dev install-docs format lint isort-lint black-lint flake8-lint unit coverage test freeze freeze-upgrade\
	freeze-base freeze-dev freeze-docs freeze-upgrade-base freeze-upgrade-dev freeze-upgrade-docs
