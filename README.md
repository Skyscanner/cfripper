# cfripper

Lambda function to "rip apart" a CloudFormation template and check it for security compliance.

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

To add custom rules first extend the [Rule](cfripper/model/rule_processor.py) class. The implement the `invoke` method by adding your logic.

CFripper uses [pycfmodel](https://github.com/Skyscanner/pycfmodel) to create a Python model of the CloudFormation script. This model is passed to the `invoke` function as the `resources` parameter. You can use the model's itterate through the resources and other objects of the model and use the helper functions to perform various checks. Look at the [current rules](cfripper/rules) for examples.

## Monitor Mode
By default, each rule has `MONITOR_MODE` set to false. Monitor model will return the failed rules in another field in the responce, instead in the main "failed rules". This way new rules can be tested before they are removed from monitor mode and start triggering alarms.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) file to add a contribution.
