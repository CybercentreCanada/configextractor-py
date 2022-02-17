# CAPE framework
import os
import sys
import yaml

from configextractor.frameworks.base import Framework
from importlib.machinery import SourceFileLoader


class CAPE(Framework):
    @staticmethod
    def validate_parsers(parsers):

        # Some parsers, like CAPE, require modules that isn't pip packaged (ie. Cuckoo lib)
        # for d_path in parsers['libraries']:
        #     sys.path.append(d_path)

        # Helper function for CAPE validation

        def is_valid(parser_path: str):
            parser_name = os.path.basename(parser_path)

            if not parser_path.endswith('.py') or parser_name.startswith('test_'):
                # If file is marked as a test file or isn't a python file, ignore
                return False

            # All CAPE parsers contain a common function that gets called on for analysis
            try:
                parser = SourceFileLoader(parser_name, parser_path).load_module()
                if hasattr(parser, 'extract_config'):
                    return True
            except Exception as e:
                raise e

        new_parsers = []
        for path in parsers:
            if os.path.isdir(path):
                # Recurse through the directory and find the exact path to the parsers
                for root, _, files in os.walk(path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        if is_valid(file_path):
                            new_parsers.append(file_path)
            else:
                if is_valid(path):
                    new_parsers.append(path)
        return new_parsers

    @ staticmethod
    def run(sample_path, parsers):
        results = dict()

        def run_parser_on_sample(sample_path, parser_path):
            sample_pt = open(sample_path, 'r', errors='ignore').read()
            sample_enc = open(sample_path, 'rb').read()

            for sample in [sample_pt, sample_enc]:
                try:
                    # Just run CAPE parsers as-is
                    parser_name = os.path.basename(parser_path)
                    parser = SourceFileLoader(parser_name, parser_path).load_module()
                    result = parser.extract_config(sample)
                    if result:
                        return {parser_name: result}
                except:
                    continue
        for parser_path in parsers:
            result = run_parser_on_sample(sample_path, parser_path)
            results.update(result) if result else None

        return results
