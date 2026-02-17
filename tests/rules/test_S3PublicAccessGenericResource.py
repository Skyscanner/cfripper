"""
Tests for S3 public access rules when the S3 bucket is parsed as a GenericResource
instead of S3Bucket (e.g. when GenericResource._strict is False and S3BucketProperties
validation fails due to unknown CloudFormation properties).

In this scenario, resource.Properties is a Generic object which does NOT have an
AccessControl attribute unless the template explicitly sets one. Accessing
resource.Properties.AccessControl directly raises AttributeError.
"""

from pycfmodel.model.cf_model import CFModel
from pycfmodel.model.generic import Generic
from pycfmodel.model.resources.generic_resource import GenericResource
from pycfmodel.model.resources.properties.policy_document import PolicyDocument
from pycfmodel.model.resources.properties.statement import Statement
from pycfmodel.model.resources.s3_bucket_policy import S3BucketPolicy, S3BucketPolicyProperties

from cfripper.config.config import Config
from cfripper.rules.s3_public_access import (
    S3BucketPublicReadAclAndListStatementRule,
    S3BucketPublicReadAclRule,
    S3BucketPublicReadWriteAclRule,
)


def _make_generic_s3_bucket(**extra_props):
    """Create a GenericResource mimicking an S3 bucket with Generic properties."""
    props = {"BucketName": "fakebucketfakebucket", **extra_props}
    return GenericResource.model_construct(
        Type="AWS::S3::Bucket",
        Properties=Generic(**props),
    )


def _make_s3_bucket_policy(bucket_name, actions):
    """Create an S3BucketPolicy resource referencing a bucket with list actions."""
    return S3BucketPolicy(
        Type="AWS::S3::BucketPolicy",
        Properties=S3BucketPolicyProperties(
            Bucket=bucket_name,
            PolicyDocument=PolicyDocument(
                Statement=[
                    Statement(
                        Effect="Allow",
                        Action=actions,
                        Resource=f"arn:aws:s3:::{bucket_name}/*",
                        Principal={"AWS": ["156460612806"]},
                    )
                ]
            ),
        ),
    )


class TestS3BucketPublicReadWriteAclRuleWithGenericResource:
    def test_no_error_when_bucket_is_generic_resource_without_access_control(self):
        """Rule should not crash when Properties is Generic without AccessControl.

        Note: S3BucketPublicReadWriteAclRule uses RESOURCE_TYPES = (S3Bucket,) so
        GenericResource instances are skipped by the isinstance check in ResourceSpecificRule.
        This test verifies no crash occurs.
        """
        bucket = _make_generic_s3_bucket()
        cfmodel = CFModel(Resources={"S3Bucket": bucket})

        rule = S3BucketPublicReadWriteAclRule(Config())
        result = rule.invoke(cfmodel)
        assert result.valid

    def test_no_error_when_generic_resource_has_public_read_write(self):
        """GenericResource with PublicReadWrite is silently skipped by ResourceSpecificRule."""
        bucket = _make_generic_s3_bucket(AccessControl="PublicReadWrite")
        cfmodel = CFModel(Resources={"S3Bucket": bucket})

        rule = S3BucketPublicReadWriteAclRule(Config())
        result = rule.invoke(cfmodel)
        # GenericResource is not in RESOURCE_TYPES so resource_invoke is never called
        assert result.valid


class TestS3BucketPublicReadAclRuleWithGenericResource:
    def test_no_error_when_bucket_is_generic_resource_without_access_control(self):
        """Rule should not crash when Properties is Generic without AccessControl."""
        bucket = _make_generic_s3_bucket()
        cfmodel = CFModel(Resources={"S3Bucket": bucket})

        rule = S3BucketPublicReadAclRule(Config())
        result = rule.invoke(cfmodel)
        assert result.valid

    def test_no_error_when_generic_resource_has_public_read(self):
        """GenericResource with PublicRead is silently skipped by ResourceSpecificRule."""
        bucket = _make_generic_s3_bucket(AccessControl="PublicRead")
        cfmodel = CFModel(Resources={"S3Bucket": bucket})

        rule = S3BucketPublicReadAclRule(Config())
        result = rule.invoke(cfmodel)
        # GenericResource is not in RESOURCE_TYPES so resource_invoke is never called
        assert result.valid


class TestS3BucketPublicReadAclAndListStatementRuleWithGenericResource:
    def test_no_error_when_referenced_bucket_is_generic_resource_without_access_control(self):
        """Rule should not crash when a policy references a bucket that is GenericResource without AccessControl."""
        bucket = _make_generic_s3_bucket()
        policy = _make_s3_bucket_policy("S3Bucket", ["s3:List*"])
        cfmodel = CFModel(Resources={"S3Bucket": bucket, "S3BucketPolicy": policy})

        rule = S3BucketPublicReadAclAndListStatementRule(Config())
        result = rule.invoke(cfmodel)
        assert result.valid

    def test_detects_public_read_acl_with_list_on_generic_resource(self):
        """Rule should detect PublicRead + List when bucket is a GenericResource."""
        bucket = _make_generic_s3_bucket(AccessControl="PublicRead")
        policy = _make_s3_bucket_policy("S3Bucket", ["s3:List*"])
        cfmodel = CFModel(Resources={"S3Bucket": bucket, "S3BucketPolicy": policy})

        rule = S3BucketPublicReadAclAndListStatementRule(Config())
        result = rule.invoke(cfmodel)
        assert not result.valid
        assert len(result.failures) == 1
        assert "public read acl and list bucket statement" in result.failures[0].reason
