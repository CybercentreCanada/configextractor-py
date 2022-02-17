import os
import pytest
from configextractor.main import validate_configuration

PARSER_CONFIGURATION = f'{os.path.dirname(os.path.realpath(__file__))}/config.yaml'


@pytest.fixture
def config():
    return validate_configuration(PARSER_CONFIGURATION)


@pytest.fixture
def sample():
    return ""


def test_cape(config, sample):
    from configextractor.frameworks import CAPE
    assert config.get('CAPE')
    CAPE.run(sample, config['CAPE'])


def test_malduck(config, sample):
    from configextractor.frameworks import MALDUCK
    assert config.get('MALDUCK')
    MALDUCK.run(sample, config['MALDUCK'])


def test_mwcp(config, sample):
    from configextractor.frameworks import MWCP
    assert config.get('MWCP')
    MWCP.run(sample, config['MWCP'])


def test_rat(config, sample):
    from configextractor.frameworks import RATDECODER
    assert config.get('RATDECODER')
    RATDECODER.run(sample, config['RATDECODER'])

    # def test_all():

    # def test_carted():
