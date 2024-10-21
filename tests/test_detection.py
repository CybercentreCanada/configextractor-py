import pytest

from configextractor.main import ConfigExtractor


@pytest.fixture
def cx():
    yield ConfigExtractor(["tests/parsers"])


def test_general_detection(cx):
    # Check to see if we actually detected any of the test parsers
    assert cx.parsers


def test_cape_detection(cx):
    # Ensure the CAPE parser was detected and NOT the class wrapping a similar CAPE function signature
    # A confusion in detection can throw off automated systems like Assemblyline
    assert "parsers.cape_extractor" in cx.parsers
    assert "parsers.cape_extractor.CAPEWrapper" not in cx.parsers


def test_maco_detection(cx):
    # Ensure the subclass was detected
    assert "parsers.maco_extractor.TestMACO" in cx.parsers
    assert "parsers.maco_extractor.Extractor" not in cx.parsers


def test_mwcp_detection(cx):
    # Ensure the subclass was detected
    assert "parsers.mwcp_extractor.TestMWCP" in cx.parsers
    assert "parsers.mwcp_extractor.Parser" not in cx.parsers


@pytest.mark.parametrize(
    "repository_url, extractor_path, extractors",
    [
        (
            "https://github.com/jeFF0Falltrades/rat_king_parser",
            "rat_king_parser",
            ["rat_king_parser.extern.maco.rkp_maco.RKPMACO"],
            10,
        ),
        (
            "https://github.com/apophis133/apophis-YARA-Rules",
            "apophis-YARA-Rules",
            [
                "apophis-YARA-Rules.scripts.maco_extractors.Pikabot_V3_C2.Pikabot",
                "apophis-YARA-Rules.scripts.maco_extractors.TrueBot_C2.TrueBot",
                "apophis-YARA-Rules.scripts.maco_extractors.metastealer_decrypt_strings.MetaStealer",
            ],
            8,
        ),
    ],
    ids=("jeFF0Falltrades/rat_king_parser", "apophis133/apophis-YARA-Rules"),
)
def test_public_projects(repository_url: str, extractor_path: str, extractors: list, python_minor: int):
    # Ensure that any changes we make doesn't break usage of public projects
    # which can affect downstream systems using like library (ie. Assemblyline)
    import os
    import sys

    from git import Repo
    from tempfile import TemporaryDirectory

    if sys.version_info >= (3, python_minor):
        with TemporaryDirectory() as working_dir:
            project_name = repository_url.rsplit("/", 1)[1]
            Repo.clone_from(repository_url, os.path.join(working_dir, project_name))

            cx = ConfigExtractor([os.path.join(working_dir, extractor_path)], create_venv=True)
            assert set(extractors) == set(cx.parsers.keys())
