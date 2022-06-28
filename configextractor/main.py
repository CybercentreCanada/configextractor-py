# Main module for ConfigExtractor library
from locale import getlocale
import os
import yara

from collections import defaultdict
from configextractor.frameworks import CAPE, MALDUCK, MWCP, RATDECODER, MACO

from logging import getLogger, Logger


class ConfigExtractor:
    def __init__(self, parsers_dir, logger: Logger = None, parser_blocklist=[]) -> None:
        if not logger:
            logger = getLogger()
        self.FRAMEWORK_LIBRARY_MAPPING = {
            'CAPE': CAPE(logger),
            'MACO': MACO(logger),
            # 'MALDUCK': MALDUCK(logger),
            # 'MWCP': MWCP(logger),
            # 'RATDECODER': RATDECODER(logger),
        }
        self.parser_blocklist = parser_blocklist

        parsers = [os.path.join(root, file) for root, _, files in os.walk(parsers_dir)
                   for file in files if file.endswith('.py')]
        self.standalone_parsers = defaultdict(list)
        # Determine what kind of parser these are and extract the yara_rules
        self._yara_rules = list()
        validated_parsers = list()
        for fw_name, fw_class in self.FRAMEWORK_LIBRARY_MAPPING.items():
            fw_parsers = fw_class.validate_parsers(parsers)
            validated_parsers.extend(fw_parsers)
            yara_rules, standalone_parsers = fw_class.extract_yara(fw_parsers)
            self._yara_rules.extend(yara_rules)
            self.standalone_parsers[fw_name].extend(standalone_parsers)

        self.yara = yara.compile(source='\n'.join(self._yara_rules))
        self.parsers = validated_parsers

    def run_parsers(self, sample):
        results = dict()
        parsers_to_run = defaultdict(lambda: defaultdict(list))
        for yara_match in self.yara.match(sample):
            # Retrieve relevant parser information
            parser_path = yara_match.meta.get('parser_path')
            parser_framework = yara_match.meta.get('parser_framework')
            if any(pname in self.parser_blocklist for pname in [parser_path, os.path.basename(parser_path)[-3]]):
                # If instructed to block, then block
                continue

            # Pass in yara.Match objects since some framework can leverage it
            parsers_to_run[parser_framework][parser_path].append(yara_match)

        for framework, parser_list in parsers_to_run.items():
            results[framework] = self.FRAMEWORK_LIBRARY_MAPPING[framework].run(sample, parser_list)

        # Run Standalone parsers after YARA-dependent
        for framework, parser_list in self.standalone_parsers.items():
            parser_list = {parser: [] for parser in parser_list
                           if any(pname in self.parser_blocklist for pname in [parser, os.path.basename(parser)[-3]])}
            result = self.FRAMEWORK_LIBRARY_MAPPING[framework].run(sample, parser_list)
            if results.get(framework):
                results[framework].update()
            else:
                results[framework] = result

        return results
