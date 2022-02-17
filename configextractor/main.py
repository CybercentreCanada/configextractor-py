# Main module for ConfigExtractor library
from collections import defaultdict
from email.policy import default
import os
import sys
import json
import yaml
from configextractor.frameworks import CAPE, MALDUCK, MWCP, RATDECODER

FRAMEWORK_LIBRARY_MAPPING = {
    'CAPE': CAPE,
    'MALDUCK': MALDUCK,
    'MWCP': MWCP,
    'RATDECODER': RATDECODER,
}


def validate_configuration(parser_config_path) -> dict():
    parser_config = dict()
    config = yaml.safe_load(open(parser_config_path, 'r').read())

    for framework, parsers in config.items():
        # Preprocess parser list in case of relative file paths
        valid_parsers = list()
        for parser in parsers:
            if parser.startswith('.'):
                parser = os.path.join(os.path.dirname(parser_config_path), parser)
            valid_parsers.append(parser)
        parser_config[framework] = FRAMEWORK_LIBRARY_MAPPING[framework].validate_parsers(valid_parsers)

    # Return validated configuration back to calling function
    config.update(parser_config)
    return config


def run_parsers(sample, parser_config):
    results = dict()
    for framework, parser_list in parser_config.items():
        results[framework] = FRAMEWORK_LIBRARY_MAPPING[framework].run(parser_list, sample)

    return results
