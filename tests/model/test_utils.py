import pytest

from cfripper.model.utils import InvalidURLException, extract_bucket_name_and_path_from_url


@pytest.mark.parametrize(
    "template_url, bucket, path",
    [
        ("https://cf-templates.s3.amazonaws.com/path/to/template.yml", "cf-templates", "path/to/template.yml"),
        (
            "https://cf-templates.s3-eu-central-1.amazonaws.com/path/to/template.yml",
            "cf-templates",
            "path/to/template.yml",
        ),
        ("https://s3.amazonaws.com/cf-templates/path/to/template.yml", "cf-templates", "path/to/template.yml"),
        (
            "https://s3.eu-central-1.amazonaws.com/cf-templates/path/to/template.yml",
            "cf-templates",
            "path/to/template.yml",
        ),
        (
            "https://s3-eu-central-1.amazonaws.com/cf-templates/path/to/template.yml",
            "cf-templates",
            "path/to/template.yml",
        ),
        (
            "https://cf-templates.s3.eu-central-1.amazonaws.com/path/to/template.yml",
            "cf-templates",
            "path/to/template.yml",
        ),
    ],
)
def test_extract_bucket_name_and_path_from_url_works(template_url, bucket, path):
    assert extract_bucket_name_and_path_from_url(template_url) == (bucket, path)


@pytest.mark.parametrize(
    "template_url",
    [
        ("https://cf-templatesXs3Xamazonaws.com/path/to/template.yml"),
        ("https://cf-templatesXs3-eu-central-1Xamazonaws.com/path/to/template.yml"),
        ("https://s3Xamazonaws.com/cf-templates/path/to/template.yml"),
        ("https://s3Xeu-central-1XamazonawsXcom/cf-templates/path/to/template.yml"),
        ("https://s3-eu-central-1XamazonawsXcom/cf-templates/path/to/template.yml"),
    ],
)
def test_extract_bucket_name_and_path_from_url_fail(template_url):
    with pytest.raises(InvalidURLException):
        extract_bucket_name_and_path_from_url(template_url)
