# MALDUCK framework

import inspect
import os
import mwcp

from configextractor.frameworks.base import Framework
from importlib.machinery import SourceFileLoader
from mwcp import Parser
from typing import List, Dict


class MWCP(Framework):
    def validate_parsers(self, parsers: List[str]) -> List[str]:

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
                self.log.error(e)

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

    def run(self, sample_path: str, parsers: Dict[str, List[str]]) -> Dict[str, dict]:
        results = dict()

        def run_parser_on_sample(sample_path, parser_path):
            try:
                # Just run MWCP parsers directly, using the filename to fetch the class attribute from module
                parser_name = os.path.basename(parser_path).strip('.py')
                parser = SourceFileLoader(parser_name, parser_path).load_module()

                # Find the attribute with that's an instance of the Parser class
                for _, mod_object in inspect.getmembers(parser):
                    if inspect.isclass(mod_object):
                        if issubclass(mod_object, Parser) and mod_object is not Parser:
                            result = mwcp.run(mod_object, data=open(sample_path, 'rb').read()).as_dict()
                            if result and not result.get('errors'):
                                return {parser_name: result}
                            return None
            except Exception as e:
                self.log.error(e)

        for parser_path in parsers:
            result = run_parser_on_sample(sample_path, parser_path)
            results.update(result) if result else None
        return results
