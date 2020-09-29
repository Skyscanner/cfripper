SOURCES = $(shell find . -name "*.py")

clean:
	rm -f lambda.zip
	rm -rf package

install:
	pip install -r requirements.txt

install-dev: install
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
	CUSTOM_COMPILE_COMMAND="make freeze" pip-compile --no-emit-index-url --output-file requirements.txt setup.py

freeze-upgrade:
	CUSTOM_COMPILE_COMMAND="make freeze-upgrade" pip-compile --no-emit-index-url --upgrade --output-file requirements.txt setup.py

lambda.zip: $(SOURCES) Makefile requirements.txt
	if [ -f lambda.zip ]; then rm lambda.zip; fi
	if [ -d "./package" ]; then rm -rf package/; fi
	pip install -t package -r requirements.txt
	cp -r cfripper package/cfripper
	cd ./package && zip -rq ../lambda.zip .
	rm -rf ./package

.PHONY: clean install install-dev format lint isort-lint black-lint flake8-lint unit coverage test freeze freeze-upgrade