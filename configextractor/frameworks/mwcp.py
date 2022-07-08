# MALDUCK framework

import inspect
import mwcp
import os
import plyara
import yara

from configextractor.frameworks.base import Framework
from importlib.machinery import SourceFileLoader
from mwcp import Parser
from plyara.utils import rebuild_yara_rule
from typing import List, Dict, Tuple


class MWCP(Framework):
    @staticmethod
    def get_parser_class(parser_path):
        parser_name = os.path.basename(parser_path)
        parser = SourceFileLoader(parser_name, parser_path).load_module()
        for _, mod_object in inspect.getmembers(parser):
            if inspect.isclass(mod_object):
                if issubclass(mod_object, Parser) and mod_object is not Parser:
                    return mod_object

    @staticmethod
    def get_name(parser_path):
        parser = SourceFileLoader(parser_path, parser_path).load_module()

        # Find the attribute with that's an instance of the Parser class
        for _, mod_object in inspect.getmembers(parser):
            if inspect.isclass(mod_object):
                if issubclass(mod_object, Parser) and mod_object is not Parser:
                    return mod_object.__name__

    def extract_yara(self, parsers: List[str]) -> Tuple[List[str], List[str]]:
        yara_rules = list()
        standalone_parsers = list()
        # Typically stored in a variable called 'rule_source'
        for parser_path in parsers:
            parser_name = os.path.basename(parser_path)
            parser = SourceFileLoader(parser_name, parser_path).load_module()

            if hasattr(parser, 'yara_rule'):
                # Modify YARA rule to include meta about the parser
                yara_parser = plyara.Plyara()
                yara_rule_frag = yara_parser.parse_string(parser.rule_source)[0]
                if not yara_rule_frag.get('metadata'):
                    yara_rule_frag['metadata'] = list()
                yara_rule_frag['metadata'].extend([{'parser_path': parser_path}, {'parser_framework': 'CAPE'}])
                rebuilt_rule = rebuild_yara_rule(yara_rule_frag)
                try:
                    yara.compile(source=rebuilt_rule)
                    yara_rules.append(rebuilt_rule)
                except Exception as e:
                    self.log.error(f"{parser_path}: {e}")
            else:
                # Assume that this parser can run on any sample
                standalone_parsers.append(parser_path)

        return yara_rules, standalone_parsers

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
                if (hasattr(parser, 'Parser') and parser.Parser == Parser) or \
                        (hasattr(parser, 'mwcp') and parser.mwcp.Parser == Parser):
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
                parser = MWCP.get_parser_class(parser_path)()
                result = mwcp.run(parser, data=open(sample_path, 'rb').read()).as_dict()
                if result:
                    [self.log.error(e) for e in result.get('errors', [])]
                    if result.get('metadata'):
                        return {parser.__name__: result}
                return None
            except Exception as e:
                self.log.error(e)

        for parser_path in parsers:
            result = run_parser_on_sample(sample_path, parser_path)
            results.update(result) if result else None
        return results
