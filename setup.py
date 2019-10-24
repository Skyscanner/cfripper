from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

install_requires = ["boto3>=1.4.7,<2", "PyYAML>=4.2b1", "pycfmodel>=0.4.0", "cfn_flip>=1.2.0"]

dev_requires = ["flake8>=3.3.0", "pytest>=3.6", "pytest-cov>=2.5.1", "pip-tools==2.0.2", "moto==1.3.13"]

setup(
    name="cfripper",
    version="0.8.1",
    author="Skyscanner Product Security",
    author_email="security@skyscanner.net",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Skyscanner/cfripper",
    description='Lambda function to "rip apart" a CloudFormation template and check it for security compliance.',
    packages=find_packages(),
    platforms="any",
    python_requires=">=3.7",
    install_requires=install_requires,
    tests_require=dev_requires,
    extras_require={"dev": dev_requires},
)
