# RATDECODER framework

import inspect
import os
from typing import List, Dict
from importlib.machinery import SourceFileLoader
from configextractor.frameworks.base import Framework
from subprocess import run as run_subprocess
import json

from malwareconfig.fileparser import FileParser
from malwareconfig.common import Decoder
import malwareconfig
import inspect


class RATDECODER(Framework):
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
                if hasattr(parser, 'Decoder') and parser.Decoder == Decoder:
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
        file_info = FileParser(sample_path)
        # Compile list of decoders
        decoders = list()
        for parser_path in parsers:
            parser_name = os.path.basename(parser_path).strip('.py')
            parser = SourceFileLoader(parser_name, parser_path).load_module()
            for _, mod_object in inspect.getmembers(parser):
                if inspect.isclass(mod_object):
                    if issubclass(mod_object, Decoder) and mod_object is not Decoder:
                        decoders.append(mod_object)

        for decoder in decoders:
            try:
                module = decoder()
                module.set_file(file_info)
                module.get_config()
                if module.config:
                    results.update({module.decoder_name: module.config})
            except:
                pass

        return results
