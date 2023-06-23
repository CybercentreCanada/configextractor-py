# RATDECODER framework (not officially supported)

import inspect
import os

from configextractor.frameworks.base import Framework
from malwareconfig.common import Decoder
from malwareconfig.fileparser import FileParser
from importlib.machinery import SourceFileLoader
from typing import List, Dict


class RATDECODER(Framework):
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
                if hasattr(parser, 'Decoder') and parser.Decoder == Decoder:
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
        results = dict
        file_info = FileParser(sample_path)
        # Compile list of decoders
        decoders = list()
        for parser_path in parsers:
            parser_name = os.path.basename(parser_path).strip('.py')
            parser = SourceFileLoader(parser_name, parser_path).load_module()
            for _, mod_object in inspect.getmembers(parser):
                if inspect.isclass(mod_object):
                    if issubclass(mod_object, Decoder) and mod_object is not Decoder:
                        decoder = mod_object()
                        decoder.set_file(file_info)
                        try:
                            decoder.get_config()
                            if decoder.config:
                                results.update({decoder.decoder_name: decoder.config})
                        except Exception as e:
                            # Log exception to get passed back to caller
                            self.log.error(e)
                            continue

        return results
