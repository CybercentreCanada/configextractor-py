from tempfile import NamedTemporaryFile

import pytest

from configextractor.frameworks import CAPE, MACO, MWCP
from configextractor.main import ConfigExtractor, Extractor


@pytest.fixture
def cx():
    import os
    import shutil

    dir = os.path.dirname(__file__)
    shutil.copytree(os.path.join(dir, "parsers"), os.path.join(dir, "venv_parsers"), dirs_exist_ok=True)
    yield ConfigExtractor(["tests/venv_parsers"])


def test_finalize_uri(cx):
    # Bug: URIs prepended with an extra protocol because it thought it was missing because of casing difference
    results = [{"config": {"http": [{"uri": "https://bad.com", "protocol": "HTTPS"}]}}]
    cx.finalize(results)
    assert results[0]["config"]["http"][0]["uri"] == "https://bad.com"


def test_venv(cx):
    cape: Extractor = cx.parsers["venv_parsers.cape_extractor"]
    maco: Extractor = cx.parsers["venv_parsers.maco_extractor.TestMACO"]
    mwcp: Extractor = cx.parsers["venv_parsers.mwcp_extractor.TestMWCP"]

    # Create a test file to run with the extractors
    with NamedTemporaryFile(delete=False) as sample:
        # Test running CAPE extractors in venv mode
        try:
            CAPE(logger=None).run_in_venv(sample_path=sample.name, extractor=cape)
        except NotImplementedError:
            # There is currently no implementation to run CAPE extractors in venv mode
            assert True

        # Test running MACO extractors in venv mode
        assert MACO(logger=None).run_in_venv(sample_path=sample.name, extractor=maco)

        # Test running MWCP extractors in venv mode
        assert MWCP(logger=None).run_in_venv(sample_path=sample.name, extractor=mwcp)
