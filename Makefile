SOURCE_DIRS = cfripper tests docs
SOURCE_FILES = setup.py
SOURCE_ALL = $(SOURCE_DIRS) $(SOURCE_FILES)

install:
	pip install -r requirements.txt

install-dev:
	pip install -e ".[dev]"

install-docs:
	pip install -e ".[dev,docs]"

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

freeze:
	CUSTOM_COMPILE_COMMAND="make freeze" pip-compile --no-emit-index-url --no-annotate --output-file requirements.txt setup.py

freeze-upgrade:
	CUSTOM_COMPILE_COMMAND="make freeze" pip-compile --no-emit-index-url --upgrade --no-annotate --output-file requirements.txt setup.py

.PHONY: install install-dev install-docs format lint isort-lint black-lint flake8-lint unit coverage test freeze freeze-upgrade
