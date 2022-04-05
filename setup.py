from pathlib import Path

from setuptools import find_packages, setup

from cfripper.__version__ import __version__

project_root_path = Path(__file__).parent

install_requires = [
    "boto3>=1.4.7,<2",
    "cfn_flip>=1.2.0",
    "click>=8.0.0",
    "pluggy~=0.13.1",
    "pycfmodel>=0.18.0",
    "pydash~=4.7.6",
    "PyYAML>=4.2b1",
]

dev_requires = [
    "black==22.3.0",
    "flake8>=3.3.0",
    "isort==4.3.21",
    "pytest>=3.6",
    "pytest-cov>=2.5.1",
    "pip-tools>=5.3.1",
    "moto==1.3.14",
]

docs_requires = [
    "ansi2html==1.5.2",
    "Markdown==3.2.2",
    "markdown-include==0.5.1",
    "mkdocs-exclude==1.0.2",
    "mkdocs-macros-plugin==0.4.9",
    "mkdocs-material==5.5.12",
    "mkdocs-material-extensions==1.0",
    "mkdocs-minify-plugin==0.3.0",
    "mkdocs==1.1.2",
    "pygments==2.5.2",
]

setup(
    name="cfripper",
    version=__version__,
    author="Skyscanner Product Security",
    author_email="security@skyscanner.net",
    entry_points={"console_scripts": ["cfripper=cfripper.cli:cli"]},
    long_description=(project_root_path / "README.md").read_text(),
    long_description_content_type="text/markdown",
    url="https://github.com/Skyscanner/cfripper",
    description="Library and CLI tool for analysing CloudFormation templates and check them for security compliance.",
    packages=find_packages(exclude=("docs", "tests")),
    platforms="any",
    python_requires=">=3.7",
    install_requires=install_requires,
    tests_require=dev_requires,
    extras_require={"dev": dev_requires, "docs": docs_requires},
)
