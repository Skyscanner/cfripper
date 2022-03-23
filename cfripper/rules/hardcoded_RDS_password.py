__all__ = ["HardcodedRDSPasswordRule"]

from typing import Dict, Optional

from pycfmodel.model.cf_model import CFModel
from pycfmodel.model.parameter import Parameter
from pycfmodel.model.resources.generic_resource import GenericResource

from cfripper.model.enums import RuleGranularity
from cfripper.model.result import Result
from cfripper.rules.base_rules import Rule


class HardcodedRDSPasswordRule(Rule):
    """
    Checks that any RDS clusters or instances aren't exposing their passwords.
    The rule forbids default password parameters and any missing `NoEcho` for RDS passwords.

    Risk:
        Not setting this correctly can lead to malicious agents attempting to gain access to your
        RDS instaces with a default password, or by reading the value that will be printed in plain
        text in the AWS console and logs if `NoEcho` is not set.

    Fix:
        When defining a password **do not use** the default value.
        If you specify a default password and you don’t provide a parameter, it will use the default
        which can be found clear text in the CloudFormation file.

    Code for fix:
        ````yml
        Parameters:
          MasterUserPassword:
            NoEcho: true
            Description: The database admin account password
            MinLength: 8
            Type: String

        ...

        Resources:
          RDSCluster:
            Type: AWS::RDS::DBCluster
            DeletionPolicy: "Snapshot"
            Properties:
              ...
              MasterUserPassword: !Ref 'MasterUserPassword'
              ...
        ````

    Filters context:
        | Parameter               | Type                             | Description                                                    |
        |:-----------------------:|:--------------------------------:|:--------------------------------------------------------------:|
        |`config`                 | str                              | `config` variable available inside the rule                    |
        |`extras`                 | str                              | `extras` variable available inside the rule                    |
        |`logical_id`             | str                              | ID used in Cloudformation to refer the resource being analysed |
        |`resource`               | `Resource`                       | Resource that is being addressed                               |
    """

    REASON_DEFAULT = "Default RDS {} password parameter (readable in plain-text) for {}."
    REASON_MISSING_NOECHO = "RDS {} password parameter missing NoEcho for {}."
    GRANULARITY = RuleGranularity.RESOURCE

    def invoke(self, cfmodel: CFModel, extras: Optional[Dict] = None) -> Result:
        result = Result()
        password_protected_cluster_ids = []
        instances_to_check = []

        for logical_id, resource in cfmodel.Resources.items():
            # flag insecure RDS Clusters.
            if resource.Type == "AWS::RDS::DBCluster":
                failure_added = self._failure_added(result, logical_id, resource, extras)
                if not failure_added:
                    password_protected_cluster_ids.append(logical_id)

            # keep track of RDS instances so they can be examined in the code below.
            elif resource.Type == "AWS::RDS::DBInstance":
                instances_to_check.append((logical_id, resource))

        # check each instance with the context of clusters.
        for logical_id, resource in instances_to_check:
            db_cluster_id = getattr(resource.Properties, "DBClusterIdentifier", None)

            if db_cluster_id and any(cluster_id in db_cluster_id for cluster_id in password_protected_cluster_ids):
                continue

            self._failure_added(result, logical_id, resource, extras)
        return result

    def _failure_added(
        self, result: Result, logical_id: str, resource: GenericResource, extras: Optional[Dict] = None
    ) -> bool:
        master_user_password = getattr(resource.Properties, "MasterUserPassword", Parameter.NO_ECHO_NO_DEFAULT)
        resource_type = resource.Type.replace("AWS::RDS::DB", "")
        if master_user_password == Parameter.NO_ECHO_WITH_DEFAULT:
            self.add_failure_to_result(
                result,
                self.REASON_DEFAULT.format(resource_type, logical_id),
                resource_ids={logical_id},
                context={"config": self._config, "extras": extras, "logical_id": logical_id, "resource": resource},
                resource_types={resource.Type},
            )
            return True
        elif master_user_password not in (Parameter.NO_ECHO_NO_DEFAULT, Parameter.NO_ECHO_WITH_VALUE):
            self.add_failure_to_result(
                result,
                self.REASON_MISSING_NOECHO.format(resource_type, logical_id),
                resource_ids={logical_id},
                context={"config": self._config, "extras": extras, "logical_id": logical_id, "resource": resource},
                resource_types={resource.Type},
            )
            return True

        return False
