"""
Copyright 2018-2019 Skyscanner Ltd

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
"""
__all__ = ["HardcodedRDSPasswordRule"]
from pycfmodel.model.parameter import Parameter

from cfripper.model.enums import RuleGranularity
from cfripper.model.rule import Rule


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
    """

    REASON_DEFAULT = "Default RDS {} password parameter (readable in plain-text) for {}."
    REASON_MISSING_NOECHO = "RDS {} password parameter missing NoEcho for {}."
    GRANULARITY = RuleGranularity.RESOURCE

    def invoke(self, cfmodel):
        password_protected_cluster_ids = []
        instances_to_check = []

        for logical_id, resource in cfmodel.Resources.items():
            # flag insecure RDS Clusters.
            if resource.Type == "AWS::RDS::DBCluster":
                failure_added = self._failure_added(logical_id, resource)
                if not failure_added:
                    password_protected_cluster_ids.append(logical_id)

            # keep track of RDS instances so they can be examined in the code below.
            elif resource.Type == "AWS::RDS::DBInstance":
                instances_to_check.append((logical_id, resource))

        # check each instance with the context of clusters.
        for logical_id, resource in instances_to_check:
            if resource.Properties.get("DBClusterIdentifier") and any(
                cluster_id in resource.Properties.get("DBClusterIdentifier")
                for cluster_id in password_protected_cluster_ids
            ):
                continue

            self._failure_added(logical_id, resource)

    def _failure_added(self, logical_id, resource) -> bool:
        master_user_password = resource.Properties.get("MasterUserPassword", Parameter.NO_ECHO_NO_DEFAULT)
        resource_type = resource.Type.replace("AWS::RDS::DB", "")
        if master_user_password == Parameter.NO_ECHO_WITH_DEFAULT:
            self.add_failure(
                type(self).__name__, self.REASON_DEFAULT.format(resource_type, logical_id), resource_ids={logical_id}
            )
            return True
        elif master_user_password not in (Parameter.NO_ECHO_NO_DEFAULT, Parameter.NO_ECHO_WITH_VALUE):
            self.add_failure(
                type(self).__name__,
                self.REASON_MISSING_NOECHO.format(resource_type, logical_id),
                resource_ids={logical_id},
            )
            return True

        return False
