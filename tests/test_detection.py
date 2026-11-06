import pytest
from scamshield.detection import is_suspicious

@pytest.mark.parametrize("url,expected", [
    ("https://g00gle.com", True),
    ("http://paypal.com", False),
    ("http://paypa1.com", True),
    ("http://xn--pypal-4ve.com", True),  # punycode homograph
    ("http://example.org", False),
])
def test_is_suspicious(url, expected):
    assert is_suspicious(url) == expected
