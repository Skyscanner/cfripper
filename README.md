<img src="docs/images/logo.png" width="200">

# CFripper

[![Build Status](https://travis-ci.org/Skyscanner/cfripper.svg?branch=master)](https://travis-ci.org/Skyscanner/cfripper)
[![PyPI version](https://badge.fury.io/py/cfripper.svg)](https://badge.fury.io/py/cfripper)

Lambda function to "rip apart" a CloudFormation template and check it for security compliance.

## Sample pipeline with CFripper

CFripper is a Python tool that aims to prevent vulnerabilities from getting to production infrastructure through vulnerable CloudFormation scripts. As with the other security tools that we use at Skyscanner, CFripper is part of the CI/CD pipeline. It runs just before a CloudFormation stack is deployed or updated and if the CloudFormation script fails to pass the security check it fails the deployment and notifies the team that owns the stack. This is an example of how you might set up CFripper as an AWS Lambda:
![CFripperPipeline](docs/images/cfripper.png)

Another approach that we use at Skyscanner is the Infrastructure as Code pipeline. Code is built and tested using drone and then our internal CD tool deals with calling CFripper to validate the script and then trigger the deployment of the infrastructure provided that the CloudFormation script is valid:
![CFripperPipeline](docs/images/cfripper2.png)

## Developing

The project comes with a set of commands you can use to run common operations:

- `make install`: Installs run time dependencies.
- `make install-dev`: Installs dev dependencies together with run time dependencies.
- `make freeze`: Freezes dependencies from `setup.py` to `requirements.txt` (including transitive ones).
- `make lint`: Runs static analysis.
- `make coverage`: Runs all tests collecting coverage.
- `make test`: Runs `lint` and `component`.


## Running the simulator

To run the simulator make sure you have the dependencies installed using `make install-dev` and run `python simulator/simulator.py`
You can add more scripts to the test set in `simulator/test_cf_scripts`.
Be sure to also add them in the `scripts` dictionary with their name, service name and project so that the simulator can pick them up.

## Custom Rules

To add custom rules first extend the [Rule](cfripper/model/rule_processor.py) class. Then implement the `invoke` method by adding your logic.

CFripper uses [pycfmodel](https://github.com/Skyscanner/pycfmodel) to create a Python model of the CloudFormation script. This model is passed to the `invoke` function as the `resources` parameter. You can use the model's iterate through the resources and other objects of the model and use the helper functions to perform various checks. Look at the [current rules](cfripper/rules) for examples.

![CFripperRule](docs/images/rule.png)

## Monitor Mode
By default, each rule has `MONITOR_MODE` set to false. Monitor model will return the failed rules in another field in the response, instead in the main "failed rules". This way new rules can be tested before they are removed from monitor mode and start triggering alarms.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) file to add a contribution.

## Attribution
Some of our rules were inspired by [cfn-nag](https://github.com/stelligent/cfn_nag). We also use their example scripts in our test cases.
