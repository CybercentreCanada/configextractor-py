from tempfile import NamedTemporaryFile

import os
import pytest

from configextractor.frameworks import MACO, MWCP
from configextractor.main import ConfigExtractor, Extractor

TESTS_DIR = os.path.dirname(__file__)


@pytest.fixture
def cx():
    import os
    import shutil

    dir = os.path.dirname(__file__)
    shutil.copytree(os.path.join(dir, "parsers"), os.path.join(dir, "venv_parsers"), dirs_exist_ok=True)
    yield ConfigExtractor([f"{TESTS_DIR}/venv_parsers"], create_venv=True)


def test_finalize_uri(cx):
    # Bug: URIs prepended with an extra protocol because it thought it was missing because of casing difference
    results = [{"config": {"http": [{"uri": "https://bad.com", "protocol": "HTTPS"}]}}]
    cx.finalize(results)
    assert results[0]["config"]["http"][0]["uri"] == "https://bad.com"


def test_venv(cx):
    maco: Extractor = cx.parsers["venv_parsers.maco_extractor.MACO"]
    mwcp: Extractor = cx.parsers["venv_parsers.mwcp_extractor.MWCP"]

    # Create a test file to run with the extractors
    with NamedTemporaryFile(delete=False) as sample:
        # Test running MACO extractors in venv mode
        assert MACO(logger=None).run_in_venv(sample_path=sample.name, extractor=maco)

        # Test running MWCP extractors in venv mode
        assert MWCP(logger=None).run_in_venv(sample_path=sample.name, extractor=mwcp)


def test_itty_bitty_file(cx):
    file_content = b"Hello world"

    # Create a small test file to run with the extractor
    with NamedTemporaryFile(delete=False) as sample:
        sample.write(file_content)
        sample.flush()

        assert cx.run_parsers(sample.name)["MACO"][0]["config"]["decoded_strings"] == [file_content.decode()]


def test_uri_expansion(cx):
    # If only a URI is provided in the results, then let's fill in what we know
    result = {"config": {"http": [{"uri": "https://abc:80/path/to?string=true#hello"}]}}
    cx.finalize([result])
    assert result["config"]["http"][0] == {
        "uri": "https://abc:80/path/to?string=true#hello",
        "protocol": "http",
        "hostname": "abc",
        "port": 80,
        "path": "/path/to",
        "query": "string=true",
        "fragment": "hello",
    }
