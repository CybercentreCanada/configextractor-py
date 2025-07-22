"""Tests for ConfigExtractor to detect extractors from supported frameworks."""

import os
from typing import List

import pytest

from configextractor.main import ConfigExtractor

TESTS_DIR = os.path.dirname(__file__)

CAPE_EXTRACTORS = [
    "community.modules.parsers.MACO.AgentTesla.AgentTesla",
    "community.modules.parsers.MACO.AsyncRAT.AsyncRAT",
    "community.modules.parsers.MACO.AuroraStealer.AuroraStealer",
    "community.modules.parsers.MACO.Azorult.Azorult",
    "community.modules.parsers.MACO.BackOffLoader.BackOffLoader",
    "community.modules.parsers.MACO.BackOffPOS.BackOffPOS",
    "community.modules.parsers.MACO.BitPaymer.BitPaymer",
    "community.modules.parsers.MACO.BlackDropper.BlackDropper",
    "community.modules.parsers.MACO.BlackNix.BlackNix",
    "community.modules.parsers.MACO.Blister.Blister",
    "community.modules.parsers.MACO.BruteRatel.BruteRatel",
    "community.modules.parsers.MACO.BuerLoader.BuerLoader",
    "community.modules.parsers.MACO.BumbleBee.BumbleBee",
    "community.modules.parsers.MACO.Carbanak.Carbanak",
    "community.modules.parsers.MACO.ChChes.ChChes",
    "community.modules.parsers.MACO.CobaltStrikeBeacon.CobaltStrikeBeacon",
    "community.modules.parsers.MACO.CobaltStrikeStager.CobaltStrikeStager",
    "community.modules.parsers.MACO.DCRat.DCRat",
    "community.modules.parsers.MACO.DarkGate.DarkGate",
    "community.modules.parsers.MACO.DoppelPaymer.DoppelPaymer",
    "community.modules.parsers.MACO.DridexLoader.DridexLoader",
    "community.modules.parsers.MACO.Emotet.Emotet",
    "community.modules.parsers.MACO.Enfal.Enfal",
    "community.modules.parsers.MACO.EvilGrab.EvilGrab",
    "community.modules.parsers.MACO.Fareit.Fareit",
    "community.modules.parsers.MACO.Formbook.Formbook",
    "community.modules.parsers.MACO.Greame.Greame",
    "community.modules.parsers.MACO.GuLoader.GuLoader",
    "community.modules.parsers.MACO.HttpBrowser.HttpBrowser",
    "community.modules.parsers.MACO.IcedID.IcedID",
    "community.modules.parsers.MACO.IcedIDLoader.IcedIDLoader",
    "community.modules.parsers.MACO.KoiLoader.KoiLoader",
    "community.modules.parsers.MACO.Latrodectus.Latrodectus",
    "community.modules.parsers.MACO.LokiBot.LokiBot",
    "community.modules.parsers.MACO.Lumma.Lumma",
    "community.modules.parsers.MACO.NanoCore.NanoCore",
    "community.modules.parsers.MACO.Nighthawk.Nighthawk",
    "community.modules.parsers.MACO.Njrat.Njrat",
    "community.modules.parsers.MACO.Oyster.Oyster",
    "community.modules.parsers.MACO.Pandora.Pandora",
    "community.modules.parsers.MACO.PhemedroneStealer.PhemedroneStealer",
    "community.modules.parsers.MACO.PikaBot.PikaBot",
    "community.modules.parsers.MACO.PlugX.PlugX",
    "community.modules.parsers.MACO.PoisonIvy.PoisonIvy",
    "community.modules.parsers.MACO.Punisher.Punisher",
    "community.modules.parsers.MACO.QakBot.QakBot",
    "community.modules.parsers.MACO.QuasarRAT.QuasarRAT",
    "community.modules.parsers.MACO.Quickbind.Quickbind",
    "community.modules.parsers.MACO.RCSession.RCSession",
    "community.modules.parsers.MACO.REvil.REvil",
    "community.modules.parsers.MACO.RedLeaf.RedLeaf",
    "community.modules.parsers.MACO.RedLine.RedLine",
    "community.modules.parsers.MACO.Remcos.Remcos",
    "community.modules.parsers.MACO.Retefe.Retefe",
    "community.modules.parsers.MACO.Rhadamanthys.Rhadamanthys",
    "community.modules.parsers.MACO.Rozena.Rozena",
    "community.modules.parsers.MACO.SmallNet.SmallNet",
    "community.modules.parsers.MACO.SmokeLoader.SmokeLoader",
    "community.modules.parsers.MACO.Socks5Systemz.Socks5Systemz",
    "community.modules.parsers.MACO.SparkRAT.SparkRAT",
    "community.modules.parsers.MACO.SquirrelWaffle.SquirrelWaffle",
    "community.modules.parsers.MACO.Stealc.Stealc",
    "community.modules.parsers.MACO.Strrat.Strrat",
    "community.modules.parsers.MACO.TSCookie.TSCookie",
    "community.modules.parsers.MACO.TrickBot.TrickBot",
    "community.modules.parsers.MACO.UrsnifV3.UrsnifV3",
    "community.modules.parsers.MACO.VenomRat.VenomRAT",
    "community.modules.parsers.MACO.WarzoneRAT.WarzoneRAT",
    "community.modules.parsers.MACO.XWorm.XWorm",
    "community.modules.parsers.MACO.XenoRAT.XenoRAT",
    "community.modules.parsers.MACO.Zloader.Zloader",
]


@pytest.mark.parametrize(
    "repository_url, extractors, python_minor, branch",
    [
        (f"file://{TESTS_DIR}/parsers", ["parsers.maco_extractor.MACO", "parsers.mwcp_extractor.MWCP"], 8, None),
        (
            "https://github.com/jeFF0Falltrades/rat_king_parser",
            ["rat_king_parser.extern.maco.rkp_maco.RKPMACO"],
            10,
            None,
        ),
        ("https://github.com/CAPESandbox/community", CAPE_EXTRACTORS, 10, None),
    ],
    ids=(
        "configextractor-py/test_extractors",
        "jeFF0Falltrades/rat_king_parser",
        "CAPESandbox/community",
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
            assert set(extractors) == set(cx.parsers.keys())
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
