import pytest
import os

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


@pytest.fixture
def cx():
    yield ConfigExtractor([f"{TESTS_DIR}/parsers"])


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
    "repository_url, extractors, python_minor, branch",
    [
        (
            "https://github.com/jeFF0Falltrades/rat_king_parser",
            ["rat_king_parser.extern.maco.rkp_maco.RKPMACO"],
            10,
            None,
        ),
        (
            "https://github.com/apophis133/apophis-YARA-Rules",
            [
                "apophis-YARA-Rules.scripts.maco_extractors.Pikabot_V3_C2.Pikabot",
                "apophis-YARA-Rules.scripts.maco_extractors.TrueBot_C2.TrueBot",
                "apophis-YARA-Rules.scripts.maco_extractors.metastealer_decrypt_strings.MetaStealer",
            ],
            8,
            None,
        ),
        ("https://github.com/cccs-rs/community", CAPE_EXTRACTORS, 10, None),
    ],
    ids=("jeFF0Falltrades/rat_king_parser", "apophis133/apophis-YARA-Rules", "CAPESandbox/community"),
)
def test_public_projects(repository_url: str, extractors: list, python_minor: int, branch: str):
    # Ensure that any changes we make doesn't break usage of public projects
    # which can affect downstream systems using like library (ie. Assemblyline)
    import os
    import sys

    # Remove local 'git' module from being loaded
    print(sys.path)
    sys.path.pop(0)
    sys.modules.pop("git", None)

    from git import Repo
    from tempfile import TemporaryDirectory

    if sys.version_info >= (3, python_minor):
        with TemporaryDirectory() as working_dir:
            project_name = repository_url.rsplit("/", 1)[1]
            extractor_dir = os.path.join(working_dir, project_name)
            Repo.clone_from(repository_url, extractor_dir, depth=1, branch=branch)

            cx = ConfigExtractor([extractor_dir], create_venv=True)
            assert set(extractors) == set(cx.parsers.keys())
    else:
        pytest.skip("Unsupported Python version")


def test_module_conflict():
    import sys
    from tempfile import TemporaryDirectory
    import shutil

    # Import the actual git package and not the local directory for this test
    if TESTS_DIR in sys.path:
        sys.path.remove(TESTS_DIR)
    sys.modules.pop("git", None)
    import git

    # Targetted directories that have the same name as an installed package should't prevent loading extractors
    ex_dir = f"{TESTS_DIR}/git"
    cx = ConfigExtractor([ex_dir])
    assert cx.parsers
    assert all([id.startswith("git") for id in cx.parsers.keys()])

    run_1 = cx.parsers

    # Loading the same extractor directory twice from different parent directories should yield the same results
    # (ie. caching from the Python interpreter shouldn't get in the way and cause the library to think it's an installed package with the same name and mess around with the scripts paths and module names)
    with TemporaryDirectory() as ex_copy:
        copy_ex_dir = f"{ex_copy}/git"
        shutil.copytree(ex_dir, copy_ex_dir, dirs_exist_ok=True)
        cx = ConfigExtractor([copy_ex_dir])
        assert cx.parsers and set(cx.parsers.keys()) == set(run_1.keys())

        # Assert no phantom paths were created in either run
        assert [os.path.exists(extractor.module_path) for extractor in list(cx.parsers.values()) + list(run_1.values())]
