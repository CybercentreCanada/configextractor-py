import inspect
import os
import plyara
import yara


from configextractor.frameworks.base import Framework
from importlib.machinery import SourceFileLoader
from maco.extractor import Extractor
from plyara.utils import rebuild_yara_rule
from typing import List, Dict, Tuple


class MACO(Framework):
    @staticmethod
    def get_classification(parser_path):
        parser = SourceFileLoader(parser_path, parser_path).load_module()
        for _, mod_object in inspect.getmembers(parser):
            if inspect.isclass(mod_object) and issubclass(mod_object, Extractor) and mod_object is not Extractor:
                return mod_object().sharing
        return None

    @staticmethod
    def get_name(parser_path):
        parser = SourceFileLoader(parser_path, parser_path).load_module()
        for _, mod_object in inspect.getmembers(parser):
            if inspect.isclass(mod_object) and issubclass(mod_object, Extractor) and mod_object is not Extractor:
                return mod_object.__name__
        return None

    def extract_yara(self, parsers: List[str]) -> Tuple[List[str], List[str]]:
        yara_rules = list()
        standalone_parsers = list()
        # Typically stored in a variable called 'rule_source'
        for parser_path in parsers:
            parser_name = os.path.basename(parser_path)
            parser = SourceFileLoader(parser_name, parser_path).load_module()
            for _, mod_object in inspect.getmembers(parser):
                if inspect.isclass(mod_object):
                    if issubclass(mod_object, Extractor) and mod_object is not Extractor:
                        decoder = mod_object()

                        if hasattr(decoder, 'yara_rule'):
                            # Modify YARA rule to include meta about the parser
                            yara_parser = plyara.Plyara()
                            yara_rule_frag = yara_parser.parse_string(decoder.yara_rule)[0]
                            if not yara_rule_frag.get('metadata'):
                                yara_rule_frag['metadata'] = list()
                            yara_rule_frag['metadata'].extend(
                                [{'parser_path': parser_path},
                                 {'parser_framework': 'MACO'}])
                            rebuilt_rule = rebuild_yara_rule(yara_rule_frag)
                            try:
                                yara.compile(source=rebuilt_rule)
                                yara_rules.append(rebuilt_rule)
                            except Exception as e:
                                self.log.error(f"{parser_path}: {e}")
                        else:
                            # In reality, a YARA rule should always be defined but just-in-case
                            standalone_parsers.append(parser_path)
                        break

        return yara_rules, standalone_parsers

    def validate_parsers(self, parsers: List[str]) -> List[str]:
        # Helper function for MaCo validation
        new_parsers = list()
        for parser_path in parsers:
            parser_name = os.path.basename(parser_path)

            if parser_name.startswith('test_') or parser_name == '__init__.py':
                # If file is marked as a test file or isn't a python file, ignore
                continue

            try:
                parser = SourceFileLoader(parser_name, parser_path).load_module()
                for _, mod_object in inspect.getmembers(parser):
                    if inspect.isclass(mod_object) and \
                            issubclass(mod_object, Extractor) and mod_object is not Extractor:
                        new_parsers.append(parser_path)
                        break
            except Exception as e:
                self.log.error(e)

        return new_parsers

    def run(self, sample_path: str, parsers: Dict[str, List[str]]) -> Dict[str, dict]:
        results = dict()
        for parser_path, yara_matches in parsers.items():
            parser_name = os.path.basename(parser_path)
            parser = SourceFileLoader(parser_name, parser_path).load_module()
            for _, mod_object in inspect.getmembers(parser):
                if inspect.isclass(mod_object):
                    if issubclass(mod_object, Extractor) and mod_object is not Extractor:
                        try:
                            decoder = mod_object()
                            # Run MaCo parser with YARA matches
                            result = decoder.run(open(sample_path, 'rb'), matches=yara_matches)
                            if result:
                                results[decoder.name] = result.dict(skip_defaults=True)
                        except Exception as e:
                            self.log.error(e)
                        finally:
                            break
        return results
