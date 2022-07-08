# Main module for ConfigExtractor library
import os
import regex
import sys
import yara

from collections import defaultdict
from configextractor.frameworks import CAPE, MACO, MWCP

from logging import getLogger, Logger
from typing import Dict

PARSER_FRAMEWORKS = [CAPE, MACO, MWCP]


class ConfigExtractor:
    @staticmethod
    def get_details(parser_path) -> Dict[str, str]:
        # Determine framework
        for framework in PARSER_FRAMEWORKS:
            if framework(logger=None).validate_parsers([parser_path]):
                # Extract details about parser
                return {
                    'framework': framework.__name__,
                    'classification': framework.get_classification(parser_path),
                    'name': framework.get_name(parser_path)
                }
        return None

    def __init__(self, parsers_dir, logger: Logger = None, parser_blocklist=[], check_extension=True) -> None:
        if not logger:
            logger = getLogger()
        self.log = logger
        self.FRAMEWORK_LIBRARY_MAPPING = {fw_cls.__name__: fw_cls(logger) for fw_cls in PARSER_FRAMEWORKS}

        parsers = list()
        self.log.debug('Adding directories within parser directory in case of local dependencies')
        self.log.debug(f'Adding {os.path.join(parsers_dir, os.pardir)} to PATH')
        sys.path.append(os.path.join(parsers_dir, os.pardir))
        for root, _, files in os.walk(parsers_dir):
            parsers.extend([os.path.join(root, file) for file in files if (check_extension and file.endswith('.py'))])
            self.log.debug(f'Adding {root} to PATH')
            sys.path.append(root)

        parsers = [os.path.join(root, file) for root, _, files in os.walk(parsers_dir) for file in files
                   if (check_extension and file.endswith('.py'))]
        self.standalone_parsers = defaultdict(list)
        self.parsers = list()
        # Determine what kind of parser these are and extract the yara_rules
        self._yara_rules = list()
        validated_parsers = list()
        for fw_name, fw_class in self.FRAMEWORK_LIBRARY_MAPPING.items():
            fw_parsers = [parser_path for parser_path in fw_class.validate_parsers(parsers) if not any(
                regex.match(blocked_parser, parser_path) for blocked_parser in parser_blocklist)]
            self.parsers.extend(fw_parsers)
            # Remove parsers from set that have already been validated against a framework
            [parsers.remove(vp) for vp in fw_parsers]
            yara_rules, standalone_parsers = fw_class.extract_yara(fw_parsers)
            self._yara_rules.extend(yara_rules)
            self.standalone_parsers[fw_name].extend(standalone_parsers)

        self.yara = yara.compile(source='\n'.join(self._yara_rules))

        self.log.debug(f"# of YARA-dependent parsers: {len(self.parsers)}")
        self.log.debug(f"# of YARA rules extracted from parsers: {len(self._yara_rules)}")
        [self.log.debug(f"# of standalone {k} parsers: {len(v)}") for k, v in self.standalone_parsers.items()]
        if parser_blocklist:
            self.log.info(f"Ignoring output from the following parsers matching: {parser_blocklist}")

    def run_parsers(self, sample, parser_blocklist=[]):
        results = dict()
        parsers_to_run = defaultdict(lambda: defaultdict(list))
        for yara_match in self.yara.match(sample):
            # Retrieve relevant parser information
            parser_path = yara_match.meta.get('parser_path')
            parser_framework = yara_match.meta.get('parser_framework')

            # Pass in yara.Match objects since some framework can leverage it
            parsers_to_run[parser_framework][parser_path].append(yara_match)

        for framework, parser_list in parsers_to_run.items():
            if parser_list:
                self.log.debug(
                    f'Running the following under the {framework} framework with YARA: {list(parser_list.keys())}')
                results[framework] = self.FRAMEWORK_LIBRARY_MAPPING[framework].run(sample, parser_list)

        # Run Standalone parsers after YARA-dependent
        for framework, parser_list in self.standalone_parsers.items():
            parser_list = {parser: [] for parser in parser_list
                           if not any(pname in parser_blocklist for pname in [parser, os.path.basename(parser)[-3]])}
            if parser_list:
                self.log.debug(f'Running the following under the {framework} framework: {list(parser_list.keys())}')
                result = self.FRAMEWORK_LIBRARY_MAPPING[framework].run(sample, parser_list)
                if results.get(framework):
                    results[framework].update()
                else:
                    results[framework] = result

        return results
