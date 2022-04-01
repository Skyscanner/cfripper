AWS_ELB_LOGS_ACCOUNT_IDS = [
    # From https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/enable-access-logs.html
    "009996457667",  # Elastic Load Balancing Account ID - Europe (Paris)
    "027434742980",  # Elastic Load Balancing Account ID - US West (N. California)
    "033677994240",  # Elastic Load Balancing Account ID - US East (Ohio)
    "037604701340",  # Elastic Load Balancing Account ID - China (Ningxia)
    "048591011584",  # Elastic Load Balancing Account ID - AWS GovCloud (US-West)
    "054676820928",  # Elastic Load Balancing Account ID - Europe (Frankfurt)
    "076674570225",  # Elastic Load Balancing Account ID - Middle East (Bahrain)
    "098369216593",  # Elastic Load Balancing Account ID - Africa (Cape Town)
    "114774131450",  # Elastic Load Balancing Account ID - Asia Pacific (Singapore)
    "127311923021",  # Elastic Load Balancing Account ID - US East (N. Virginia)
    "156460612806",  # Elastic Load Balancing Account ID - Europe (Ireland)
    "190560391635",  # Elastic Load Balancing Account ID - AWS GovCloud (US-East)
    "383597477331",  # Elastic Load Balancing Account ID - Asia Pacific (Osaka)
    "507241528517",  # Elastic Load Balancing Account ID - South America (São Paulo)
    "582318560864",  # Elastic Load Balancing Account ID - Asia Pacific (Tokyo)
    "600734575887",  # Elastic Load Balancing Account ID - Asia Pacific (Seoul)
    "635631232127",  # Elastic Load Balancing Account ID - Europe (Milan)
    "638102146993",  # Elastic Load Balancing Account ID - China (Beijing)
    "652711504416",  # Elastic Load Balancing Account ID - Europe (London)
    "718504428378",  # Elastic Load Balancing Account ID - Asia Pacific (Mumbai)
    "754344448648",  # Elastic Load Balancing Account ID - Asia Pacific (Hong Kong)
    "783225319266",  # Elastic Load Balancing Account ID - Asia Pacific (Sydney)
    "797873946194",  # Elastic Load Balancing Account ID - US West (Oregon)
    "897822967062",  # Elastic Load Balancing Account ID - Europe (Stockholm)
    "985666609251",  # Elastic Load Balancing Account ID - Canada (Central)
]

AWS_CLOUDTRAIL_ACCOUNT_IDS = [
    # From https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-supported-regions.html
    "034638983726",  # CloudTrail Account ID - Middle East (Bahrain)
    "035351147821",  # CloudTrail Account ID - Europe (Frankfurt)
    "086441151436",  # CloudTrail Account ID - US East (N. Virginia)
    "113285607260",  # CloudTrail Account ID - US West (Oregon)
    "119688915426",  # CloudTrail Account ID - Asia Pacific (Hong Kong)
    "193415116832",  # CloudTrail Account ID - China (Beijing)
    "216624486486",  # CloudTrail Account ID - Asia Pacific (Tokyo)
    "262312530599",  # CloudTrail Account ID - Europe (Paris)
    "282025262664",  # CloudTrail Account ID - Europe (London)
    "284668455005",  # CloudTrail Account ID - Asia Pacific (Sydney)
    "388731089494",  # CloudTrail Account ID - US West (N. California)
    "475085895292",  # CloudTrail Account ID - US East (Ohio)
    "492519147666",  # CloudTrail Account ID - Asia Pacific (Seoul)
    "525921808201",  # CloudTrail Account ID - Africa (Cape Town)
    "608710470296",  # CloudTrail Account ID - AWS GovCloud (US-West)
    "669305197877",  # CloudTrail Account ID - Europe (Milan)
    "681348832753",  # CloudTrail Account ID - China (Ningxia)
    "765225791966",  # CloudTrail Account ID - Asia Pacific (Osaka)
    "814480443879",  # CloudTrail Account ID - South America (São Paulo)
    "819402241893",  # CloudTrail Account ID - Canada (Central)
    "829690693026",  # CloudTrail Account ID - Europe (Stockholm)
    "859597730677",  # CloudTrail Account ID - Europe (Ireland)
    "886388586500",  # CloudTrail Account ID - AWS GovCloud (US-East)
    "903692715234",  # CloudTrail Account ID - Asia Pacific (Singapore)
    "977081816279",  # CloudTrail Account ID - Asia Pacific (Mumbai)
]

AWS_REDSHIFT_AUDIT_ACCOUNT_IDS = [
    # From https://docs.aws.amazon.com/redshift/latest/mgmt/db-auditing.html#rs-db-auditing-cloud-trail-rs-acct-ids
    "041313461515",  # Redshift Audit Logs Account ID - Europe (Milan) Region
    "051362938876",  # Redshift Audit Logs Account ID - Middle East (Bahrain) Region
    "246478207311",  # Redshift Audit Logs Account ID - Europe (Ireland) Region
    "368064434614",  # Redshift Audit Logs Account ID - US East (N. Virginia) Region
    "392442076723",  # Redshift Audit Logs Account ID - South America (São Paulo) Region
    "398671365691",  # Redshift Audit Logs Account ID - Asia Pacific (Osaka) Region
    "408097707231",  # Redshift Audit Logs Account ID - Asia Pacific (Mumbai) Region
    "420376844563",  # Redshift Audit Logs Account ID - Africa (Cape Town) Region
    "434091160558",  # Redshift Audit Logs Account ID - Europe (Frankfurt) Region
    "473191095985",  # Redshift Audit Logs Account ID - US West (Oregon) Region
    "485979073181",  # Redshift Audit Logs Account ID - Asia Pacific (Sydney) Region
    "553461782468",  # Redshift Audit Logs Account ID - Europe (Stockholm) Region
    "615915377779",  # Redshift Audit Logs Account ID - Asia Pacific (Tokyo) Region
    "651179539253",  # Redshift Audit Logs Account ID - Asia Pacific (Hong Kong) Region
    "694668203235",  # Redshift Audit Logs Account ID - Europe (Paris) Region
    "703715109447",  # Redshift Audit Logs Account ID - US West (N. California) Region
    "713597048934",  # Redshift Audit Logs Account ID - Asia Pacific (Seoul) Region
    "764870610256",  # Redshift Audit Logs Account ID - Canada (Central) Region
    "790247189693",  # Redshift Audit Logs Account ID - US East (Ohio) Region
    "885798887673",  # Redshift Audit Logs Account ID - Europe (London) Region
    "960118270566",  # Redshift Audit Logs Account ID - Asia Pacific (Singapore) Region
]


AWS_ELASTICACHE_BACKUP_CANONICAL_IDS = [
    # From https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/backups-exporting.html
    "b14d6a125bdf69854ed8ef2e71d8a20b7c490f252229b806e514966e490b8d83",  # China (Beijing) and China (Ningxia) Regions
    "40fa568277ad703bd160f66ae4f83fc9dfdfd06c2f1b5060ca22442ac3ef8be6",  # AWS GovCloud (US-West) Region
    "540804c33a284a299d2547575ce1010f2312ef3da9b3a053c8bc45bf233e4353",  # All other AWS Regions
]

MIN_PORT_NUMBER = 0
MAX_PORT_NUMBER = 65535
