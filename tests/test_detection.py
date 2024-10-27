import pytest

from configextractor.main import ConfigExtractor


@pytest.fixture
def cx():
    yield ConfigExtractor(["tests/parsers"])


def test_general_detection(cx):
    # Check to see if we actually detected any of the test parsers
    assert cx.parsers


def test_maco_detection(cx):
    # Ensure the subclass was detected
    assert "parsers.maco_extractor.MACO" in cx.parsers
    assert "parsers.maco_extractor.Extractor" not in cx.parsers


def test_mwcp_detection(cx):
    # Ensure the subclass was detected
    assert "parsers.mwcp_extractor.MWCP" in cx.parsers
    assert "parsers.mwcp_extractor.Parser" not in cx.parsers


@pytest.mark.parametrize(
    "repository_url, extractor_path, extractors, python_minor, branch",
    [
        (
            "https://github.com/jeFF0Falltrades/rat_king_parser",
            "rat_king_parser",
            ["rat_king_parser.extern.maco.rkp_maco.RKPMACO"],
            10,
            None,
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
            None,
        ),
    ],
    ids=("jeFF0Falltrades/rat_king_parser", "apophis133/apophis-YARA-Rules"),
)
def test_public_projects(repository_url: str, extractor_path: str, extractors: list, python_minor: int, branch: str):
    # Ensure that any changes we make doesn't break usage of public projects
    # which can affect downstream systems using like library (ie. Assemblyline)
    import os
    import sys

    from git import Repo
    from tempfile import TemporaryDirectory

    if sys.version_info >= (3, python_minor):
        with TemporaryDirectory() as working_dir:
            project_name = repository_url.rsplit("/", 1)[1]
            Repo.clone_from(repository_url, os.path.join(working_dir, project_name), depth=1, branch=branch)

            cx = ConfigExtractor([os.path.join(working_dir, extractor_path)], create_venv=True)
            assert set(extractors) == set(cx.parsers.keys())
    else:
        pytest.skip("Unsupported Python version")


CAPE_EXTRACTORS = [
    "CAPEv2.modules.processing.parsers.MACO.AgentTesla.AgentTesla",
    "CAPEv2.modules.processing.parsers.MACO.AsyncRAT.AsyncRAT",
    "CAPEv2.modules.processing.parsers.MACO.AuroraStealer.AuroraStealer",
    "CAPEv2.modules.processing.parsers.MACO.Azorult.Azorult",
    "CAPEv2.modules.processing.parsers.MACO.BackOffLoader.BackOffLoader",
    "CAPEv2.modules.processing.parsers.MACO.BackOffPOS.BackOffPOS",
    "CAPEv2.modules.processing.parsers.MACO.BitPaymer.BitPaymer",
    "CAPEv2.modules.processing.parsers.MACO.BlackDropper.BlackDropper",
    "CAPEv2.modules.processing.parsers.MACO.BlackNix.BlackNix",
    "CAPEv2.modules.processing.parsers.MACO.Blister.Blister",
    "CAPEv2.modules.processing.parsers.MACO.BruteRatel.BruteRatel",
    "CAPEv2.modules.processing.parsers.MACO.BuerLoader.BuerLoader",
    "CAPEv2.modules.processing.parsers.MACO.BumbleBee.BumbleBee",
    "CAPEv2.modules.processing.parsers.MACO.Carbanak.Carbanak",
    "CAPEv2.modules.processing.parsers.MACO.ChChes.ChChes",
    "CAPEv2.modules.processing.parsers.MACO.CobaltStrikeBeacon.CobaltStrikeBeacon",
    "CAPEv2.modules.processing.parsers.MACO.CobaltStrikeStager.CobaltStrikeStager",
    "CAPEv2.modules.processing.parsers.MACO.DCRat.DCRat",
    "CAPEv2.modules.processing.parsers.MACO.DarkGate.DarkGate",
    "CAPEv2.modules.processing.parsers.MACO.DoppelPaymer.DoppelPaymer",
    "CAPEv2.modules.processing.parsers.MACO.DridexLoader.DridexLoader",
    "CAPEv2.modules.processing.parsers.MACO.Emotet.Emotet",
    "CAPEv2.modules.processing.parsers.MACO.Enfal.Enfal",
    "CAPEv2.modules.processing.parsers.MACO.EvilGrab.EvilGrab",
    "CAPEv2.modules.processing.parsers.MACO.Fareit.Fareit",
    "CAPEv2.modules.processing.parsers.MACO.Formbook.Formbook",
    "CAPEv2.modules.processing.parsers.MACO.Greame.Greame",
    "CAPEv2.modules.processing.parsers.MACO.GuLoader.GuLoader",
    "CAPEv2.modules.processing.parsers.MACO.Hancitor.Hancitor",
    "CAPEv2.modules.processing.parsers.MACO.HttpBrowser.HttpBrowser",
    "CAPEv2.modules.processing.parsers.MACO.IcedID.IcedID",
    "CAPEv2.modules.processing.parsers.MACO.IcedIDLoader.IcedIDLoader",
    "CAPEv2.modules.processing.parsers.MACO.KoiLoader.KoiLoader",
    "CAPEv2.modules.processing.parsers.MACO.Latrodectus.Latrodectus",
    "CAPEv2.modules.processing.parsers.MACO.LokiBot.LokiBot",
    "CAPEv2.modules.processing.parsers.MACO.Lumma.Lumma",
    "CAPEv2.modules.processing.parsers.MACO.NanoCore.NanoCore",
    "CAPEv2.modules.processing.parsers.MACO.Nighthawk.Nighthawk",
    "CAPEv2.modules.processing.parsers.MACO.Njrat.Njrat",
    "CAPEv2.modules.processing.parsers.MACO.Oyster.Oyster",
    "CAPEv2.modules.processing.parsers.MACO.Pandora.Pandora",
    "CAPEv2.modules.processing.parsers.MACO.PhemedroneStealer.PhemedroneStealer",
    "CAPEv2.modules.processing.parsers.MACO.PikaBot.PikaBot",
    "CAPEv2.modules.processing.parsers.MACO.PlugX.PlugX",
    "CAPEv2.modules.processing.parsers.MACO.PoisonIvy.PoisonIvy",
    "CAPEv2.modules.processing.parsers.MACO.Punisher.Punisher",
    "CAPEv2.modules.processing.parsers.MACO.QakBot.QakBot",
    "CAPEv2.modules.processing.parsers.MACO.QuasarRAT.QuasarRAT",
    "CAPEv2.modules.processing.parsers.MACO.Quickbind.Quickbind",
    "CAPEv2.modules.processing.parsers.MACO.RCSession.RCSession",
    "CAPEv2.modules.processing.parsers.MACO.REvil.REvil",
    "CAPEv2.modules.processing.parsers.MACO.RedLeaf.RedLeaf",
    "CAPEv2.modules.processing.parsers.MACO.RedLine.RedLine",
    "CAPEv2.modules.processing.parsers.MACO.Remcos.Remcos",
    "CAPEv2.modules.processing.parsers.MACO.Retefe.Retefe",
    "CAPEv2.modules.processing.parsers.MACO.Rhadamanthys.Rhadamanthys",
    "CAPEv2.modules.processing.parsers.MACO.Rozena.Rozena",
    "CAPEv2.modules.processing.parsers.MACO.SmallNet.SmallNet",
    "CAPEv2.modules.processing.parsers.MACO.SmokeLoader.SmokeLoader",
    "CAPEv2.modules.processing.parsers.MACO.Socks5Systemz.Socks5Systemz",
    "CAPEv2.modules.processing.parsers.MACO.SparkRAT.SparkRAT",
    "CAPEv2.modules.processing.parsers.MACO.SquirrelWaffle.SquirrelWaffle",
    "CAPEv2.modules.processing.parsers.MACO.Stealc.Stealc",
    "CAPEv2.modules.processing.parsers.MACO.Strrat.Strrat",
    "CAPEv2.modules.processing.parsers.MACO.TSCookie.TSCookie",
    "CAPEv2.modules.processing.parsers.MACO.TrickBot.TrickBot",
    "CAPEv2.modules.processing.parsers.MACO.UrsnifV3.UrsnifV3",
    "CAPEv2.modules.processing.parsers.MACO.VenomRat.VenomRAT",
    "CAPEv2.modules.processing.parsers.MACO.WarzoneRAT.WarzoneRAT",
    "CAPEv2.modules.processing.parsers.MACO.XWorm.XWorm",
    "CAPEv2.modules.processing.parsers.MACO.XenoRAT.XenoRAT",
    "CAPEv2.modules.processing.parsers.MACO.Zloader.Zloader",
    "CAPEv2.modules.processing.parsers.mwcp.SmokeLoader.SmokeLoader",
]


def test_CAPEv2():
    # Ensure that any changes we make doesn't break usage of public projects
    # which can affect downstream systems using like library (ie. Assemblyline)
    import os
    import sys
    import shutil

    from git import Repo
    from tempfile import TemporaryDirectory

    # TODO: Update this respective of https://github.com/kevoreilly/CAPEv2/pull/2373
    main_repository = "https://github.com/cccs-rs/CAPEv2"
    community_repository = "https://github.com/CAPESandbox/community"
    if sys.version_info >= (3, 10):
        with TemporaryDirectory() as working_dir:
            main_folder = os.path.join(working_dir, "CAPEv2")
            community_folder = os.path.join(working_dir, "community")

            # Merge community extensions with main project
            Repo.clone_from(main_repository, main_folder, depth=1, branch="extractor/to_MACO")
            Repo.clone_from(community_repository, community_folder, depth=1)
            shutil.copytree(community_folder, main_folder, dirs_exist_ok=True)

            cx = ConfigExtractor([main_folder], create_venv=True)
            assert set(CAPE_EXTRACTORS) == set(cx.parsers.keys())
    else:
        pytest.skip("Unsupported Python version")
