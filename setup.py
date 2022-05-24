from pathlib import Path

from setuptools import find_packages, setup

from cfripper.__version__ import __version__

project_root_path = Path(__file__).parent

install_requires = [
    "boto3>=1.4.7,<2",
    "cfn_flip>=1.2.0",
    "click>=8.0.0",
    "pluggy~=0.13.1",
    "pycfmodel>=0.20.0",
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
    "moto[cloudformation,s3]==3.1.9",  # coverage fails for 3.1.10, issue is https://github.com/spulec/moto/issues/5162
]

docs_requires = [
    "click==8.1.2",
    "csscompressor==0.9.5",
    "ghp-import==2.0.2",
    "htmlmin==0.1.12",
    "importlib-metadata==4.11.3",
    "Jinja2==3.1.1",
    "jsmin==3.0.1",
    "Markdown==3.3.6",
    "MarkupSafe==2.1.1",
    "mergedeep==1.3.4",
    "mkdocs==1.3.0",
    "mkdocs-exclude==1.0.2",
    "mkdocs-macros-plugin==0.7.0",
    "mkdocs-material==8.2.8",
    "mkdocs-material-extensions==1.0.3",
    "mkdocs-minify-plugin==0.5.0",
    "packaging==21.3",
    "Pygments==2.11.2",
    "pymdown-extensions==9.3",
    "pyparsing==3.0.7",
    "python-dateutil==2.8.2",
    "PyYAML==6.0",
    "pyyaml_env_tag==0.1",
    "six==1.16.0",
    "termcolor==1.1.0",
    "watchdog==2.1.7",
    "zipp==3.8.0",
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
