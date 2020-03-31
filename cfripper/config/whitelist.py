"""
A list of projects that are allowed to skip specific checks.

The format:

whitelist = {
    "stack_name_1": [
        "rule_name_1",
        "rule_name_2",
    ],
    "stack_name_2": [
        "rule_name_2",
        "rule_name_3",
    ]
}

"""
stack_whitelist = {}

"""
A list of resources that are allowed to use wildcard principals, grouped by stack name

The format:

wildcard_principal_resource_whitelist = {
    "stack_name1": [
        "RESOURCE_NAME_1",
        "RESOURCE_NAME_2",
    ],
    "stack_name2": [
        "RESOURCE_NAME_3",
        "RESOURCE_NAME_4",
    ]
}

"""

wildcard_principal_resource_whitelist = {}

"""
A whitelist for all rules that can whitelist resources for certain stacks
stack names and resource names accept regular expressions

rule_to_resource_whitelist = {
    "rule_name_1": {
        "stack_name_1": {
            "resource_name_1",
        },
        "stack_name_2": {
            "resource_name_2",
            "resource_name_3",
        },
    },
    "rule_name_2": {
        "stack_name_1": {
            "resource_name_4",
        },
    },
}


"""
rule_to_resource_whitelist = {}

"""
A whitelist for all rules that can whitelist actions for certain stacks
stack names and actions accept regular expressions

rule_to_action_whitelist = {
    "rule_name_3": {
        "stack_name_1": {
            "aws_action:one",
        },
        "stack_name_2": {
            "raws_action:one",
            "aws_action:one",
        },
    },
    "rule_name_4": {
        "stack_name_1": {
            "aws_action:*",
        },
    },
}


"""

rule_to_action_whitelist = {}


AWS_ELB_LOGS_ACCOUNT_IDS = [
    # From https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/enable-access-logs.html
    "009996457667",  # Elastic Load Balancing Account ID - eu-west-3
    "027434742980",  # Elastic Load Balancing Account ID - us-west-1
    "033677994240",  # Elastic Load Balancing Account ID - us-east-2
    "037604701340",  # Elastic Load Balancing Account ID - cn-northwest-1*
    "048591011584",  # Elastic Load Balancing Account ID - us-gov-west-1*
    "054676820928",  # Elastic Load Balancing Account ID - eu-central-1
    "076674570225",  # Elastic Load Balancing Account ID - me-south-1
    "114774131450",  # Elastic Load Balancing Account ID - ap-southeast-1
    "127311923021",  # Elastic Load Balancing Account ID - us-east-1
    "156460612806",  # Elastic Load Balancing Account ID - eu-west-1
    "190560391635",  # Elastic Load Balancing Account ID - us-gov-east-1*
    "383597477331",  # Elastic Load Balancing Account ID - ap-northeast-3
    "507241528517",  # Elastic Load Balancing Account ID - sa-east-1
    "582318560864",  # Elastic Load Balancing Account ID - ap-northeast-1
    "600734575887",  # Elastic Load Balancing Account ID - ap-northeast-2
    "638102146993",  # Elastic Load Balancing Account ID - cn-north-1*
    "652711504416",  # Elastic Load Balancing Account ID - eu-west-2
    "718504428378",  # Elastic Load Balancing Account ID - ap-south-1
    "754344448648",  # Elastic Load Balancing Account ID - ap-east-1
    "783225319266",  # Elastic Load Balancing Account ID - ap-southeast-2
    "797873946194",  # Elastic Load Balancing Account ID - us-west-2
    "897822967062",  # Elastic Load Balancing Account ID - eu-north-1
    "985666609251",  # Elastic Load Balancing Account ID - ca-central-1
]


AWS_ELASTICACHE_BACKUP_CANONICAL_IDS = [
    # From https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/backups-exporting.html
    "b14d6a125bdf69854ed8ef2e71d8a20b7c490f252229b806e514966e490b8d83",  # China (Beijing) and China (Ningxia) Regions
    "40fa568277ad703bd160f66ae4f83fc9dfdfd06c2f1b5060ca22442ac3ef8be6",  # AWS GovCloud (US-West) Region
    "540804c33a284a299d2547575ce1010f2312ef3da9b3a053c8bc45bf233e4353",  # All other AWS Regions
]
