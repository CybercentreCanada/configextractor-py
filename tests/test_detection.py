import pytest

from configextractor.main import ConfigExtractor


@pytest.fixture
def cx():
    yield ConfigExtractor(["tests/test_parsers"])


def test_general_detection(cx):
    # Check to see if we actually detected any of the test parsers
    assert cx.parsers


def test_cape_detection(cx):
    # Ensure the CAPE parser was detected and NOT the class wrapping a similar CAPE function signature
    # A confusion in detection can throw off automated systems like Assemblyline
    assert "test_parsers.cape" in cx.parsers
    assert "test_parsers.cape.CAPEWrapper" not in cx.parsers


def test_maco_detection(cx):
    # Ensure the subclass was detected
    assert "test_parsers.maco.TestMACO" in cx.parsers
    assert "test_parsers.maco.Extractor" not in cx.parsers


def test_mwcp_detection(cx):
    # Ensure the subclass was detected
    assert "test_parsers.mwcp.TestMWCP" in cx.parsers
    assert "test_parsers.mwcp.Parser" not in cx.parsers
