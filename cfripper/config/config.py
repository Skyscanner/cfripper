import importlib
import logging
import os
import re
import sys
from typing import Dict, List

from pydantic import BaseModel

from .rule_config import RuleConfig
from .whitelist import AWS_ELASTICACHE_BACKUP_CANONICAL_IDS, AWS_ELB_LOGS_ACCOUNT_IDS
from .whitelist import rule_to_action_whitelist as default_rule_to_action_whitelist
from .whitelist import rule_to_resource_whitelist as default_rule_to_resource_whitelist
from .whitelist import stack_whitelist as default_stack_whitelist

logger = logging.getLogger(__file__)


class Config:
    DEFAULT_ALLOWED_WORLD_OPEN_PORTS = [80, 443]
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
        stack_whitelist=None,
        rule_to_action_whitelist=None,
        rule_to_resource_whitelist=None,
        rules_config=None,
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
        self.rule_to_action_whitelist = (
            rule_to_action_whitelist if rule_to_action_whitelist is not None else default_rule_to_action_whitelist
        )
        self.rule_to_resource_whitelist = (
            rule_to_resource_whitelist if rule_to_resource_whitelist is not None else default_rule_to_resource_whitelist
        )
        self.stack_whitelist = stack_whitelist if stack_whitelist is not None else default_stack_whitelist
        if aws_service_accounts is None:
            self.aws_service_accounts = {
                "elb_logs_account_ids": AWS_ELB_LOGS_ACCOUNT_IDS,
                "elasticache_backup_canonical_ids": AWS_ELASTICACHE_BACKUP_CANONICAL_IDS,
            }
        else:
            self.aws_service_accounts = aws_service_accounts

        if self.stack_name:
            whitelisted_rules = self.get_whitelisted_rules()
            # set difference to get a list of allowed rules to be ran for this stack
            self.rules = list(set(self.rules) - set(whitelisted_rules))

        self.allowed_world_open_ports = list(self.DEFAULT_ALLOWED_WORLD_OPEN_PORTS)

        self.forbidden_managed_policy_arns = list(self.DEFAULT_FORBIDDEN_MANAGED_POLICY_ARNS)

        self.forbidden_resource_star_action_prefixes = list(self.DEFAULT_FORBIDDEN_RESOURCE_STAR_ACTION_PREFIXES)

        # Set up a string list of allowed principals. If kept empty it will allow any AWS principal
        self.aws_principals = aws_principals if aws_principals is not None else []
        self.rules_config = rules_config if rules_config is not None else {}

    def get_rule_config(self, rule_name: str) -> RuleConfig:
        rule_config = self.rules_config.get(rule_name)
        if rule_config is None:
            return RuleConfig()
        elif isinstance(rule_config, RuleConfig):
            return rule_config
        return RuleConfig(**rule_config)

    def get_whitelisted_actions(self, rule_name: str) -> List[str]:
        allowed_actions = []
        for k, v in self.rule_to_action_whitelist.get(rule_name, {}).items():
            if re.match(k, self.stack_name):
                allowed_actions += v

        return allowed_actions

    def get_whitelisted_resources(self, rule_name: str) -> List[str]:
        allowed_resources = []
        for k, v in self.rule_to_resource_whitelist.get(rule_name, {}).items():
            if re.match(k, self.stack_name):
                allowed_resources += v

        return allowed_resources

    def get_whitelisted_rules(self) -> List[str]:
        whitelisted_rules = []
        for k, v in self.stack_whitelist.items():
            if re.match(k, self.stack_name):
                whitelisted_rules += v

        return whitelisted_rules

    def load_rules_config_file(self, filename: str):
        if not os.path.exists(filename):
            raise RuntimeError(f"{filename} doesn't exist")

        try:
            ext = os.path.splitext(filename)[1]
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


class RulesConfigMapping(BaseModel):
    __root__: Dict[str, RuleConfig]
