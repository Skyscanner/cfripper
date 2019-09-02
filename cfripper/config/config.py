"""
Copyright 2018 Skyscanner Ltd

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
"""

from cfripper.config.whitelist import get_stack_exemption_list


class Config:
    DEFAULT_ALLOWED_WORLD_OPEN_PORTS = ['80', '443']
    DEFAULT_FORBIDDEN_MANAGED_POLICY_ARNS = [
        'arn:aws:iam::aws:policy/AdministratorAccess',
        'arn:aws:iam::aws:policy/IAMFullAccess',
        'arn:aws:iam::aws:policy/job-function/NetworkAdministrator',
    ]
    DEFAULT_FORBIDDEN_RESOURCE_STAR_ACTION_PREFIXES = [
        # catch Action * Resource *
        '*',

        # stop S3 modifications on Resource *
        's3:Put',
        's3:Delete',

        # DynamoDB
        # http://docs.aws.amazon.com/IAM/latest/UserGuide/list_dynamodb.html
        'dynamodb:GetItem',
        'dynamodb:Delete',

        # IAM
        # http://docs.aws.amazon.com/IAM/latest/UserGuide/list_iam.html
        'iam:Add',
        'iam:Attach',
        'iam:Create',
        'iam:Delete',
        'iam:Put',
        'iam:Update'
        'iam:Remove',

        # pword / MFA STUFF
        'iam:ChangePassword',
        'iam:ResyncMFADevice',
        'iam:Deactivate',
        'iam:Enable',

        # EC2
        'ec2:DeleteCustomerGateway',
        'ec2:DeleteDhcpOptions',
        'ec2:DeleteFlowLogs',
        'ec2:DeleteInternetGateway',
        'ec2:DeleteNatGateway',

        # must keep as DeleteNetworkInterface needs to be allowed (for Lambda)
        'ec2:DeleteNetworkAcl',
        'ec2:DeleteNetworkAclEntry',

        'ec2:DeleteRoute',
        'ec2:DeleteRouteTable',
        'ec2:DeleteSecurityGroup',
        'ec2:DeleteSpotDatafeedSubscription',
        'ec2:DeleteSubnet',

        'ec2:DeleteVpc',

        'ec2:CreateSubnet',
        'ec2:CreateNatGateway',
        'ec2:CreateDhcpOptions',
        'ec2:CreateCustomerGateway',

        'ecs:*',

        # other lovely services
        'cloudtrail:',
        'aws-portal:',
        'acm:',
        'trustedadvisor:',
        'aws-marketplace',
        'directconnect:',
    ]

    def __init__(
        self,
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
    ):
        self.project_name = project_name
        self.service_name = service_name
        self.stack_name = stack_name
        self.event = event
        self.RULES = rules
        self.template_url = template_url
        self.aws_region = aws_region
        self.aws_account_name = aws_account_name
        self.aws_account_id = aws_account_id
        self.aws_user_agent = aws_user_agent

        if self.stack_name:
            exemption_list = get_stack_exemption_list(self.stack_name)

            # set difference to get a list of allowed rules to be ran for this stack
            self.RULES = list(set(self.RULES) - set(exemption_list))

        self.ALLOWED_WORLD_OPEN_PORTS = self.DEFAULT_ALLOWED_WORLD_OPEN_PORTS

        self.FORBIDDEN_MANAGED_POLICY_ARNS = self.DEFAULT_FORBIDDEN_MANAGED_POLICY_ARNS

        self.FORBIDDEN_RESOURCE_STAR_ACTION_PREFIXES = self.DEFAULT_FORBIDDEN_RESOURCE_STAR_ACTION_PREFIXES

        self.AWS_PRINCIPALS = []
