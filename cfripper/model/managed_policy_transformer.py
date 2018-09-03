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


import boto3

from pycfmodel.model.resources.properties.policy import Policy


class ManagedPolicyTransformer(object):
    """
    Go through managed policie ARNs, fetch them and add them as
    regular policies so that they can be checked by the rules.
    """

    def __init__(self, cf_model):
        self.cf_model = cf_model
        self.iam_client = boto3.client("iam")

    def transform_managed_policies(self):
        self.parse_fetch_update(
            self.cf_model.resources.get("AWS::IAM::Role", []),
        )
        self.parse_fetch_update(
            self.cf_model.resources.get("AWS::IAM::Group", []),
        )

    def parse_fetch_update(self, resources):
        for resource in resources:
            for managed_policy_arn in resource.managed_policy_arns:
                managed_policy = self.iam_client.get_policy(
                    PolicyArn=managed_policy_arn,
                )
                version_id = managed_policy.get("Policy", {}).get("DefaultVersionId")
                if not version_id:
                    continue

                policy_version = self.iam_client.get_policy_version(
                    PolicyArn=managed_policy_arn,
                    VersionId=version_id,
                )
                policy_document_json = {
                    "PolicyDocument": policy_version["PolicyVersion"]["Document"],
                    "PolicyName": "AutoTransformedManagedPolicy{}".format(version_id),
                }
                policy_document = Policy(policy_document_json)
                resource.policies.append(policy_document)
