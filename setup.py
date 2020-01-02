from pathlib import Path

from setuptools import find_packages, setup

here = Path(__file__).parent

package_name = "cfripper"

install_requires = ["boto3>=1.4.7,<2", "PyYAML>=4.2b1", "pycfmodel>=0.5.1", "cfn_flip>=1.2.0"]

dev_requires = [
    "black==19.10b0",
    "flake8>=3.3.0",
    "isort==4.3.21",
    "pytest>=3.6",
    "pytest-cov>=2.5.1",
    "pip-tools==4.2.0",
    "moto==1.3.13",
]

docs_requires = [
    "ansi2html==1.5.2",
    "markdown-include==0.5.1",
    "mkdocs-exclude==1.0.2",
    "mkdocs-macros-plugin",
    "mkdocs-material==4.5.1",
    "mkdocs==1.0.4",
    "pygments==2.5.2",
]

# Import README for long-description.
with open(here / "README.md") as f:
    long_description = f.read()

# Load the package's __version__.py module as a dictionary.
vars_from_version_file = {}
with open(here / package_name / "__version__.py") as f:
    exec(f.read(), vars_from_version_file)
version = vars_from_version_file["__version__"]

setup(
    name=package_name,
    version=version,
    author="Skyscanner Product Security",
    author_email="security@skyscanner.net",
    entry_points={"console_scripts": ["cfripper=cfripper.cli:cli"]},
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Skyscanner/cfripper",
    description='Lambda function to "rip apart" a CloudFormation template and check it for security compliance.',
    packages=find_packages(exclude=("docs", "tests")),
    platforms="any",
    python_requires=">=3.7",
    install_requires=install_requires,
    tests_require=dev_requires,
    extras_require={"dev": dev_requires, "docs": docs_requires},
)
