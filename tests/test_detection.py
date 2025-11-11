"""Tests for ConfigExtractor to detect extractors from supported frameworks."""

import os
from typing import List

import pytest

from configextractor.main import ConfigExtractor

TESTS_DIR = os.path.dirname(__file__)

CAPE_EXRACTORS = [
    "CAPE-parsers.cape_parsers.CAPE.community.AgentTesla",
    "CAPE-parsers.cape_parsers.CAPE.community.Amadey",
    "CAPE-parsers.cape_parsers.CAPE.community.Amatera",
    "CAPE-parsers.cape_parsers.CAPE.community.Arkei",
    "CAPE-parsers.cape_parsers.CAPE.community.AsyncRAT",
    "CAPE-parsers.cape_parsers.CAPE.community.AuroraStealer",
    "CAPE-parsers.cape_parsers.CAPE.community.Carbanak",
    "CAPE-parsers.cape_parsers.CAPE.community.CobaltStrikeBeacon",
    "CAPE-parsers.cape_parsers.CAPE.community.CobaltStrikeStager",
    "CAPE-parsers.cape_parsers.CAPE.community.DCRat",
    "CAPE-parsers.cape_parsers.CAPE.community.Fareit",
    "CAPE-parsers.cape_parsers.CAPE.community.KoiLoader",
    "CAPE-parsers.cape_parsers.CAPE.community.LokiBot",
    "CAPE-parsers.cape_parsers.CAPE.community.Lumma",
    "CAPE-parsers.cape_parsers.CAPE.community.MonsterV2",
    "CAPE-parsers.cape_parsers.CAPE.community.MyKings",
    "CAPE-parsers.cape_parsers.CAPE.community.NanoCore",
    "CAPE-parsers.cape_parsers.CAPE.community.Nighthawk",
    "CAPE-parsers.cape_parsers.CAPE.community.Njrat",
    "CAPE-parsers.cape_parsers.CAPE.community.PhemedroneStealer",
    "CAPE-parsers.cape_parsers.CAPE.community.QuasarRAT",
    "CAPE-parsers.cape_parsers.CAPE.community.Snake",
    "CAPE-parsers.cape_parsers.CAPE.community.SparkRAT",
    "CAPE-parsers.cape_parsers.CAPE.community.Stealc",
    "CAPE-parsers.cape_parsers.CAPE.community.VenomRAT",
    "CAPE-parsers.cape_parsers.CAPE.community.WinosStager",
    "CAPE-parsers.cape_parsers.CAPE.community.XWorm",
    "CAPE-parsers.cape_parsers.CAPE.community.XenoRAT",
    "CAPE-parsers.cape_parsers.CAPE.core.AdaptixBeacon",
    "CAPE-parsers.cape_parsers.CAPE.core.AuraStealer",
    "CAPE-parsers.cape_parsers.CAPE.core.Azorult",
    "CAPE-parsers.cape_parsers.CAPE.core.BitPaymer",
    "CAPE-parsers.cape_parsers.CAPE.core.BlackDropper",
    "CAPE-parsers.cape_parsers.CAPE.core.Blister",
    "CAPE-parsers.cape_parsers.CAPE.core.BruteRatel",
    "CAPE-parsers.cape_parsers.CAPE.core.BumbleBee",
    "CAPE-parsers.cape_parsers.CAPE.core.DarkGate",
    "CAPE-parsers.cape_parsers.CAPE.core.DoppelPaymer",
    "CAPE-parsers.cape_parsers.CAPE.core.DridexLoader",
    "CAPE-parsers.cape_parsers.CAPE.core.GuLoader",
    "CAPE-parsers.cape_parsers.CAPE.core.IcedID",
    "CAPE-parsers.cape_parsers.CAPE.core.IcedIDLoader",
    "CAPE-parsers.cape_parsers.CAPE.core.Latrodectus",
    "CAPE-parsers.cape_parsers.CAPE.core.NitroBunnyDownloader",
    "CAPE-parsers.cape_parsers.CAPE.core.Oyster",
    "CAPE-parsers.cape_parsers.CAPE.core.PikaBot",
    "CAPE-parsers.cape_parsers.CAPE.core.PlugX",
    "CAPE-parsers.cape_parsers.CAPE.core.QakBot",
    "CAPE-parsers.cape_parsers.CAPE.core.Quickbind",
    "CAPE-parsers.cape_parsers.CAPE.core.RedLine",
    "CAPE-parsers.cape_parsers.CAPE.core.Remcos",
    "CAPE-parsers.cape_parsers.CAPE.core.Rhadamanthys",
    "CAPE-parsers.cape_parsers.CAPE.core.SmokeLoader",
    "CAPE-parsers.cape_parsers.CAPE.core.Socks5Systemz",
    "CAPE-parsers.cape_parsers.CAPE.core.SquirrelWaffle",
    "CAPE-parsers.cape_parsers.CAPE.core.Strrat",
    "CAPE-parsers.cape_parsers.CAPE.core.WarzoneRAT",
    "CAPE-parsers.cape_parsers.CAPE.core.Zloader",
]


@pytest.mark.parametrize(
    "repository_url, extractors, python_minor, branch",
    [
        (
            f"file://{TESTS_DIR}/parsers",
            ["parsers.maco_extractor.MACO", "parsers.mwcp_extractor.MWCP", "parsers.cape_extractor"],
            10,
            None,
        ),
        (
            "https://github.com/jeFF0Falltrades/rat_king_parser",
            ["rat_king_parser.extern.maco.rkp_maco.RKPMACO"],
            10,
            None,
        ),
        ("https://github.com/cccs-rs/CAPE-parsers", CAPE_EXRACTORS, 10, "assemblyline"),
    ],
    ids=(
        "configextractor-py/test_extractors",
        "jeFF0Falltrades/rat_king_parser",
        "CAPESandbox/CAPE-parsers",
    ),
)
def test_public_projects(repository_url: str, extractors: List[str], python_minor: int, branch: str):
    """Test compatibility with public projects.

    Args:
      repository_url (str): URL to the repository
      extractors (List[str]): List of expected extractors to be able to detect
      python_minor (int): Minor version of Python to test with
      branch (str): Branch to clone from
    """
    # Ensure that any changes we make doesn't break usage of public projects
    # which can affect downstream systems using like library (ie. Assemblyline)
    import os
    import sys
    from tempfile import TemporaryDirectory

    from git import Repo

    if sys.version_info >= (3, python_minor):
        with TemporaryDirectory() as working_dir:
            if repository_url.startswith("file://"):
                # Local directory testing
                extractor_dir = repository_url[7:]
            else:
                project_name = repository_url.rsplit("/", 1)[1]
                extractor_dir = os.path.join(working_dir, project_name)
                Repo.clone_from(repository_url, extractor_dir, depth=1, branch=branch)

            cx = ConfigExtractor([extractor_dir], create_venv=True)
            e = cx.parsers.keys()
            assert set(extractors) == set(e)
    else:
        pytest.skip("Unsupported Python version")


def test_module_conflict():
    """Check to see if we'll run into an issue with module name conflicts.

    Test that loading the same extractor directory twice from different parent directories yields the same results.

    """
    import shutil
    from tempfile import TemporaryDirectory

    # Loading the same extractor directory twice from different parent directories should yield the same results

    previous_run = None
    for _ in range(2):
        with TemporaryDirectory() as ex_copy:
            copy_ex_dir = f"{ex_copy}/test"
            shutil.copytree(f"{TESTS_DIR}/parsers", copy_ex_dir, dirs_exist_ok=True)
            cx = ConfigExtractor([copy_ex_dir])
            assert cx.parsers

            if previous_run:
                assert set(cx.parsers.keys()) == set(previous_run.keys())

                # Assert no phantom paths were created in either run
                assert [
                    os.path.exists(extractor.module_path)
                    for extractor in list(cx.parsers.values()) + list(previous_run.values())
                ]
            else:
                previous_run = cx.parsers
