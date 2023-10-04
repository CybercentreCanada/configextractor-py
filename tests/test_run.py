import pytest

from configextractor.main import ConfigExtractor


@pytest.fixture
def cx():
    yield ConfigExtractor(["tests/test_parsers"])


def test_finalize_uri(cx):
    # Bug: URIs prepended with an extra protocol because it thought it was missing because of casing difference
    results = [{"config": {"http": [{"uri": "https://bad.com", "protocol": "HTTPS"}]}}]
    cx.finalize(results)
    assert results[0]["config"]["http"][0]["uri"] == "https://bad.com"
