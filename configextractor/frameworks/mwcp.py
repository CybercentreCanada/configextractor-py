# MALDUCK framework

import os
from typing import List, Dict
from importlib.machinery import SourceFileLoader
from configextractor.frameworks.base import Framework

from mwcp import Parser
import mwcp


class MWCP(Framework):
    @staticmethod
    def validate_parsers(parsers: List[str]):

        # Helper function for MWCP validation
        def is_valid(parser_path: str):
            parser_name = os.path.basename(parser_path)

            if not parser_path.endswith('.py') or parser_name.startswith('test_'):
                # If file is marked as a test file or isn't a python file, ignore
                return False

            # All MWCP parsers contain a common class import
            try:
                parser = SourceFileLoader(parser_name, parser_path).load_module()
                if hasattr(parser, 'Parser') and parser.Parser == Parser:
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

    @staticmethod
    def run(sample_path: str, parsers: List[str]) -> Dict[str, dict]:
        results = dict

        def run_parser_on_sample(sample_path, parser_path):
            sample_pt = open(sample_path, 'r', errors='ignore').read()
            sample_enc = open(sample_path, 'rb').read()

            for sample in [sample_pt, sample_enc]:
                try:
                    # Just run MWCP parsers directly, using the filename to fetch the class attribute from module
                    parser_name = os.path.basename(parser_path).strip('.py')
                    parser = SourceFileLoader(parser_name, parser_path).load_module()
                    result = mwcp.run(getattr(parser, parser_name), data=sample).as_dict()
                    if result:
                        return {parser_name: result}
                except:
                    continue

        for parser_path in parsers:
            result = run_parser_on_sample(sample_path, parser_path)
            results.update(result) if result else None
        return results
