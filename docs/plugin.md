To add custom rules first extend the [Rule](https://github.com/Skyscanner/cfripper/blob/master/cfripper/model/rule.py)
class. Then implement the `invoke` method by adding your logic.

{{ inline_source('cfripper.rules.base_rules.Rule.invoke') }}

CFRipper uses [pycfmodel](https://github.com/Skyscanner/pycfmodel) to create a Python model of the CloudFormation script.
This model is passed to the `invoke` function as the `cfmodel` parameter. You can use the model's iterate through the
resources and other objects of the model and use the helper functions to perform various checks. Look at the
[current rules](/rules) for examples.

## Making your rules available to CFRipper

CFRipper uses [pluggy](https://github.com/pytest-dev/pluggy) in order to load dynamic rules. You have to define an 
entrypoint for your distribution so that CFRipper finds your plugin module. Entrypoints are a feature 
provided by `setuptools`. The CFRipper CLI looks up the `cfripper` entrypoint to discover its plugins and load them.

In case that more than one rule uses the same ID, the last added will be preserved. 

CFRipper just have one hook that has to be implemented to provide custom rules. `cfripper_get_rules` hook returns a 
dictionary where key are strings and values are rule inherited classes.

### Example

This is a two file example (setup.py and plugin.py) than provides one custom rule to CFRipper. 

setup.py
```python
from setuptools import setup


setup(
    name="cfripper-shiny-new-plugin",
    install_requires="cfripper>=0.24.0,<0.25.0",
    # the following makes a plugin available to cfripper
    entry_points={"cfripper": ["shiny_new_plugin = plugin"]},
    py_modules=["plugin"],
)
```

plugin.py
```python
from typing import Dict, Optional

from cfripper.config.pluggy import hookimpl
from cfripper.model.result import Result
from cfripper.rules.base_rules import Rule
from pycfmodel.model.cf_model import CFModel


class DummyRule(Rule):
    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        print("I'm Dummy Rule Defined in a plugin!!!")
        return Result()


@hookimpl
def cfripper_get_rules():
    return {DummyRule.__name__: DummyRule}
```

After installing our module using `python setup.py install`, we can check that is available in our environment.

```
pip list
Package                   Version
------------------------- -------
boto3                     1.17.1
botocore                  1.20.1
cfn-flip                  1.2.3
cfripper                  1.0.0
cfripper-shiny-new-plugin 0.0.0
click                     7.1.2
importlib-metadata        3.4.0
jmespath                  0.10.0
pip                       20.3.3
pluggy                    0.13.1
pycfmodel                 0.8.1
pydantic                  1.7.3
pydash                    4.7.6
python-dateutil           2.8.1
PyYAML                    5.4.1
s3transfer                0.3.4
setuptools                51.0.0
six                       1.15.0
typing-extensions         3.7.4.3
urllib3                   1.26.3
wheel                     0.36.2
zipp                      3.4.0
```

When running CFRipper, it's going to load automically our rules defined at our module. So when we run it, we can see
the print defined on our Dummy Rule being executed.

```
cfripper --resolve test.json
Analysing test.json...
I'm Dummy Rule Defined in a plugin!!!
Valid: True
```
