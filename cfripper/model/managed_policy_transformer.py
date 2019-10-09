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
import boto3

from pycfmodel.model.resources.properties.policy import Policy


def transform_managed_policies(cfmodel):
    iam_client = boto3.client("iam")
    for logical_id, resource in cfmodel.Resources.items():
        if resource.Type in ["AWS::IAM::Role", "AWS::IAM::Group"] and resource.Properties.ManagedPolicyArns:
            managed_policies = []
            for managed_policy_arn in resource.Properties.ManagedPolicyArns:
                managed_policy = iam_client.get_policy(PolicyArn=managed_policy_arn)
                version_id = managed_policy.get("Policy", {}).get("DefaultVersionId")
                if version_id:
                    policy_version = iam_client.get_policy_version(PolicyArn=managed_policy_arn, VersionId=version_id)
                    managed_policies.append(
                        Policy(
                            **{
                                "PolicyDocument": policy_version["PolicyVersion"]["Document"],
                                "PolicyName": f"AutoTransformedManagedPolicy{version_id}",
                            }
                        )
                    )
            resource.Properties.ManagedPolicyArns = managed_policies
    return cfmodel