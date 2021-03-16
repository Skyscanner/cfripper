SOURCES = $(shell find . -name "*.py")

install:
	pip install -r requirements.txt

install-dev:
	pip install -e ".[dev]"

install-docs:
	pip install -e ".[dev,docs]"

format:
	isort --recursive .
	black .

lint: isort-lint black-lint flake8-lint

isort-lint:
	isort --check-only --recursive .

black-lint:
	black --check .

flake8-lint:
	flake8 cfripper/ tests/

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
