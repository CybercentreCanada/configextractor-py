# CAPE framework
import os
import plyara
import yara

from maco.model import ExtractorModel
from configextractor.frameworks.base import Framework
from importlib.machinery import SourceFileLoader
from plyara.utils import rebuild_yara_rule
from typing import Dict, List, Tuple


class CAPE(Framework):
    @staticmethod
    def get_classification(parser_path):
        parser = SourceFileLoader(parser_path, parser_path).load_module()
        if hasattr(parser, 'TLP'):
            return parser.TLP
        return None

    def extract_yara(self, parsers: List[str]) -> Tuple[List[str], List[str]]:
        yara_rules = list()
        standalone_parsers = list()
        # Typically stored in a variable called 'rule_source'
        for parser_path in parsers:
            parser_name = os.path.basename(parser_path)
            parser = SourceFileLoader(parser_name, parser_path).load_module()
            if hasattr(parser, 'rule_source'):
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
        # Helper function for CAPE validation
        def is_valid(parser_path: str):
            parser_name = os.path.basename(parser_path)

            if parser_name.startswith('test_'):
                # If file is marked as a test file or isn't a python file, ignore
                return False

            # All CAPE parsers contain a common function that gets called on for analysis
            try:
                parser = SourceFileLoader(parser_name, parser_path).load_module()
                if hasattr(parser, 'extract_config'):
                    return True
            except Exception as e:
                self.log.error(f"{parser_path}: {e}")

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
                # Just run CAPE parsers as-is
                parser_name = os.path.basename(parser_path)[:-3]
                parser = SourceFileLoader(parser_name, parser_path).load_module()
                result = parser.extract_config(open(sample_path, 'rb').read())
                if result:
                    # Just throw everthing into other for now
                    return {parser_name: {
                        'author': parser.AUTHOR,
                        'description': parser.DESCRIPTION or "",
                        'config': ExtractorModel(other=result, family=parser_name).dict(skip_defaults=True)
                    }}
            except Exception as e:
                self.log.error(f"{parser_path}: {e}")

            return {}

        for parser_path in parsers:
            result = run_parser_on_sample(sample_path, parser_path)
            results.update(result)

        return results
