import importlib
import itertools
import logging
import sys
from collections import defaultdict
from io import TextIOWrapper
from pathlib import Path
from typing import DefaultDict, Dict, List

from pydantic import BaseModel

from cfripper.config.constants import (
    AWS_CLOUDTRAIL_ACCOUNT_IDS,
    AWS_ELASTICACHE_BACKUP_CANONICAL_IDS,
    AWS_ELB_LOGS_ACCOUNT_IDS,
    AWS_REDSHIFT_AUDIT_ACCOUNT_IDS,
)

from .filter import Filter
from .rule_config import RuleConfig

logger = logging.getLogger(__file__)


class Config:
    DEFAULT_FORBIDDEN_MANAGED_POLICY_ARNS = [
        "arn:aws:iam::aws:policy/AdministratorAccess",
        "arn:aws:iam::aws:policy/IAMFullAccess",
        "arn:aws:iam::aws:policy/job-function/NetworkAdministrator",
    ]
    DEFAULT_FORBIDDEN_RESOURCE_STAR_ACTION_PREFIXES = [
        # catch Action * Resource *
        "*",
        # stop S3 modifications on Resource *
        "s3:Put",
        "s3:Delete",
        # DynamoDB
        # http://docs.aws.amazon.com/IAM/latest/UserGuide/list_dynamodb.html
        "dynamodb:GetItem",
        "dynamodb:Delete",
        # IAM
        # http://docs.aws.amazon.com/IAM/latest/UserGuide/list_iam.html
        "iam:Add",
        "iam:Attach",
        "iam:Create",
        "iam:Delete",
        "iam:Put",
        "iam:Update",
        "iam:Remove",
        # pword / MFA STUFF
        "iam:ChangePassword",
        "iam:ResyncMFADevice",
        "iam:Deactivate",
        "iam:Enable",
        # EC2
        "ec2:DeleteCustomerGateway",
        "ec2:DeleteDhcpOptions",
        "ec2:DeleteFlowLogs",
        "ec2:DeleteInternetGateway",
        "ec2:DeleteNatGateway",
        # must keep as DeleteNetworkInterface needs to be allowed (for Lambda)
        "ec2:DeleteNetworkAcl",
        "ec2:DeleteNetworkAclEntry",
        "ec2:DeleteRoute",
        "ec2:DeleteRouteTable",
        "ec2:DeleteSecurityGroup",
        "ec2:DeleteSpotDatafeedSubscription",
        "ec2:DeleteSubnet",
        "ec2:DeleteVpc",
        "ec2:CreateSubnet",
        "ec2:CreateNatGateway",
        "ec2:CreateDhcpOptions",
        "ec2:CreateCustomerGateway",
        "ecs:*",
        # other lovely services
        "cloudtrail:",
        "aws-portal:",
        "acm:",
        "trustedadvisor:",
        "aws-marketplace",
        "directconnect:",
    ]

    def __init__(
        self,
        *,
        project_name=None,
        service_name=None,
        stack_name=None,
        rules=None,
        event=None,
        template_url=None,
        aws_region=None,
        aws_account_name=None,
        aws_account_id=None,
        aws_user_agent=None,
        aws_principals=None,
        aws_service_accounts=None,
        rules_config=None,
        rules_filters=None,
    ):
        self.project_name = project_name
        self.service_name = service_name
        self.stack_name = stack_name
        self.event = event
        self.rules = rules
        self.template_url = template_url
        self.aws_region = aws_region
        self.aws_account_name = aws_account_name
        self.aws_account_id = aws_account_id
        self.aws_user_agent = aws_user_agent
        if aws_service_accounts is None:
            self.aws_service_accounts = {
                "cloudtrail_account_ids": AWS_CLOUDTRAIL_ACCOUNT_IDS,
                "elasticache_backup_canonical_ids": AWS_ELASTICACHE_BACKUP_CANONICAL_IDS,
                "elb_logs_account_ids": AWS_ELB_LOGS_ACCOUNT_IDS,
                "redshift_audit_account_ids": AWS_REDSHIFT_AUDIT_ACCOUNT_IDS,
            }
        else:
            self.aws_service_accounts = aws_service_accounts

        self.forbidden_managed_policy_arns = list(self.DEFAULT_FORBIDDEN_MANAGED_POLICY_ARNS)

        self.forbidden_resource_star_action_prefixes = list(self.DEFAULT_FORBIDDEN_RESOURCE_STAR_ACTION_PREFIXES)

        # Set up a string list of allowed principals. If kept empty it will allow any AWS principal
        self.aws_principals = aws_principals if aws_principals is not None else []

        self.rules_config = rules_config if rules_config is not None else {}
        self.rules_filters: DefaultDict[str, List[Filter]] = defaultdict(list)
        if rules_filters:
            self.add_filters(rules_filters)

    def get_rule_config(self, rule_name: str) -> RuleConfig:
        rule_config = self.rules_config.get(rule_name)
        if rule_config is None:
            return RuleConfig()
        elif isinstance(rule_config, RuleConfig):
            return rule_config
        return RuleConfig(**rule_config)

    def get_rule_filters(self, rule_name: str) -> List[Filter]:
        return self.rules_filters.get(rule_name, [])

    def load_rules_config_file(self, rules_config_file: TextIOWrapper):
        filename = rules_config_file.name

        if not Path(filename).is_file():
            raise RuntimeError(f"{filename} doesn't exist")

        try:
            ext = Path(filename).suffix
            module_name = "__rules_config__"
            if ext not in [".py", ".pyc"]:
                raise RuntimeError("Configuration file should have a valid Python extension.")
            spec = importlib.util.spec_from_file_location(module_name, filename)
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            rules_config = vars(module).get("RULES_CONFIG")
            # Validate rules_config format
            RulesConfigMapping(__root__=rules_config)
            self.rules_config = rules_config
        except Exception:
            logger.exception(f"Failed to read config file: {filename}")
            raise

    def add_filters_from_dir(self, path: str):
        if not Path(path).is_dir():
            raise RuntimeError(f"{path} doesn't exist")

        try:
            module_name = "__rules_config__"
            filenames = sorted(itertools.chain(Path(path).glob("*.py"), Path(path).glob("*.pyc")))
            for filename in filenames:
                spec = importlib.util.spec_from_file_location(module_name, filename.absolute())
                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                spec.loader.exec_module(module)
                filters = vars(module).get("FILTERS")
                if not filters:
                    continue
                # Validate filters format
                RulesFiltersMapping(__root__=filters)
                self.add_filters(filters=filters)
                logger.debug(f"{filename} loaded")
        except Exception:
            logger.exception(f"Failed to read files in path: {path}")
            raise

    def add_filters(self, filters: List[Filter]):
        for filter in filters:
            for rule in filter.rules:
                self.rules_filters[rule].append(filter)


class RulesConfigMapping(BaseModel):
    __root__: Dict[str, RuleConfig]


class RulesFiltersMapping(BaseModel):
    __root__: List[Filter]
