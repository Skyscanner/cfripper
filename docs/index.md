<img src="img/logo.png" width="200">

# CFRipper

[![Build Status](https://travis-ci.org/Skyscanner/cfripper.svg?branch=master)](https://travis-ci.org/Skyscanner/cfripper)
[![PyPI version](https://badge.fury.io/py/cfripper.svg)](https://badge.fury.io/py/cfripper)

CFRipper is a Python tool that aims to prevent vulnerabilities from getting to production infrastructure through vulnerable CloudFormation scripts. 

## Developing

The project comes with a set of commands you can use to run common operations:

- `make install`: Installs run time dependencies.
- `make install-dev`: Installs dev dependencies together with run time dependencies.
- `make freeze`: Freezes dependencies from `setup.py` to `requirements.txt` (including transitive ones).
- `make lint`: Runs static analysis.
- `make coverage`: Runs all tests collecting coverage.
- `make test`: Runs `lint` and `component`.


## Contributing

See [CONTRIBUTING.md](https://github.com/Skyscanner/cfripper/blob/master/CONTRIBUTING.md) file to add a contribution.

## Attribution
Some of our rules were inspired by [cfn-nag](https://github.com/stelligent/cfn_nag). We also use their example scripts in our test cases.
