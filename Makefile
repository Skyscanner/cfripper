SOURCES = $(shell find . -name "*.py")

clean:
	rm -f lambda.zip
	rm -rf package

install:
	pip install -r requirements.txt

install-dev: install
	pip install -e ".[dev]"

lint:
	flake8 cfripper/ # tests/

component:
	pytest -sv tests

coverage:
	coverage run --source=cfripper --branch -m pytest tests/ --junitxml=build/test.xml -v
	coverage report
	coverage xml -i -o build/coverage.xml

test: lint component

freeze:
	pip-compile --output-file requirements.txt setup.py

lambda.zip: $(SOURCES) Makefile requirements.txt
	if [ -f lambda.zip ]; then rm lambda.zip; fi
	if [ -d "./package" ]; then rm -rf package/; fi
	pip install -t package -r requirements.txt
	cp -r cfripper package/cfripper
	cd ./package && zip -rq ../lambda.zip .
	rm -rf ./package

.PHONY: install install-dev lint component coverage test freeze
