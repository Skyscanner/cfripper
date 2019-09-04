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


import pycfmodel
from unittest.mock import Mock
from cfripper.model.managed_policy_transformer import ManagedPolicyTransformer


test_cf = {
    "Resources": {
        "Test1": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "ManagedPolicyArns": ["arn:aws:iam::aws:policy/aws-service-role/AWSTrustedAdvisorServiceRolePolicy"],
                "Policies": [],
                "RoleName": "Test",
            },
        }
    }
}

test_policy = {
    "PolicyVersion": {
        "Document": {
            "Version": "2012-10-17",
            "Statement": [{"Action": ["cloudtrail:GetTrailStatus"], "Effect": "Allow", "Resource": "*"}],
        },
        "VersionId": "v2",
        "IsDefaultVersion": True,
        "CreateDate": "2018-08-21T22:29:41Z",
    }
}


def test_flow():
    cf_model = pycfmodel.parse(test_cf)
    transformer = ManagedPolicyTransformer(cf_model)
    iam_client = Mock()
    iam_client.get_policy = Mock(return_value={"Policy": {"DefaultVersionId": "TestV"}})
    iam_client.get_policy_version = Mock(return_value=test_policy)
    transformer.iam_client = iam_client

    transformer.transform_managed_policies()

    test_iam_role = cf_model.resources["AWS::IAM::Role"][0]

    assert len(test_iam_role.policies) == 1
    assert test_iam_role.policies[0].policy_name == "AutoTransformedManagedPolicyTestV"
