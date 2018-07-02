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

## Contributing
