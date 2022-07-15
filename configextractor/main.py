# Main module for ConfigExtractor library
import importlib
import inspect
import os
import pkgutil
import regex
import sys
import yara

from collections import defaultdict
from configextractor.frameworks import CAPE, MACO, MWCP

from logging import getLogger, Logger
from typing import Dict

PARSER_FRAMEWORKS = [(CAPE, 'rule_source'), (MACO, 'yara_rule'), (MWCP, None)]


class ConfigExtractor:
    def __init__(self, parsers_dir, logger: Logger = None, parser_blocklist=[], check_extension=True) -> None:
        if not logger:
            logger = getLogger()
        self.log = logger
        self.FRAMEWORK_LIBRARY_MAPPING = {fw_cls.__name__: fw_cls(
            logger, yara_attr) for fw_cls, yara_attr in PARSER_FRAMEWORKS}

        self.log.debug('Adding directories within parser directory in case of local dependencies')
        self.log.debug(f'Adding {os.path.join(parsers_dir, os.pardir)} to PATH')

        # Find extractors (taken from MaCo's Collector class)
        path_parent, foldername = os.path.split(parsers_dir)
        sys.path.insert(1, path_parent)
        mod = importlib.import_module(foldername)

        # walk packages in the extractors directory to find all extactors
        self.parsers = dict()
        yara_rules = list()
        self.standalone_parsers = defaultdict(list)
        for _, module_name, ispkg in pkgutil.walk_packages(mod.__path__, mod.__name__ + "."):
            if ispkg:
                # skip __init__.py
                continue

            self.log.debug(f"Inspecting '{module_name}' for extractors")
            # raise an exception if one of the potential extractors can't be imported
            # note that excluding an extractor through include/exclude does not prevent it being imported
            try:
                module = importlib.import_module(module_name)
            except Exception as e:
                self.log.error(e)
                continue

            # Determine if module contains parsers of a supported framework
            candidates = [module] + [member for _, member in inspect.getmembers(module)]
            for fw_name, fw_class in self.FRAMEWORK_LIBRARY_MAPPING.items():
                for member in candidates:
                    try:
                        if fw_class.validate(member):
                            self.parsers[module.__file__] = member
                            rules = fw_class.extract_yara_from_module(member, module.__file__)
                            if not rules:
                                # Standalone parser, need to know what framework to run under
                                self.standalone_parsers[fw_name].append(member)
                            else:
                                yara_rules.extend(rules)
                    except Exception as e:
                        self.log.error(f"{member}: {e}")
        self.yara = yara.compile(source='\n'.join(yara_rules))

        self.log.debug(f"# of YARA-dependent parsers: {len(self.parsers)}")
        self.log.debug(f"# of YARA rules extracted from parsers: {len(yara_rules)}")
        [self.log.debug(f"# of standalone {k} parsers: {len(v)}") for k, v in self.standalone_parsers.items()]
        if parser_blocklist:
            self.log.info(f"Ignoring output from the following parsers matching: {parser_blocklist}")

    def get_details(self, parser_path) -> Dict[str, str]:
        # Determine framework
        module = self.parsers[parser_path]
        for fw_name, fw_class in self.FRAMEWORK_LIBRARY_MAPPING.items():
            if fw_class.validate(module):
                # Extract details about parser
                return {
                    'framework': fw_name,
                    'classification': fw_class.get_classification(parser_path),
                    'name': fw_class.get_name(parser_path)
                }
        return None

    def run_parsers(self, sample, parser_blocklist=[]):
        results = dict()
        parsers_to_run = defaultdict(lambda: defaultdict(list))
        parser_names = list()

        # Get YARA-dependents parsers that should run based on match
        for yara_match in self.yara.match(sample):
            # Retrieve relevant parser information
            parser_path = yara_match.meta.get('parser_path')
            parser_framework = yara_match.meta.get('parser_framework')
            parser_names.append(yara_match.meta.get('parser_name'))

            parser_module = self.parsers[parser_path]
            # Pass in yara.Match objects since some framework can leverage it
            parsers_to_run[parser_framework][parser_module].append(yara_match)

        # Add standalone parsers that should run on any file
        for parser_framework, parser_list in self.standalone_parsers.items():
            [parsers_to_run[parser_framework][parser].extend([]) for parser in parser_list]

        for framework, parser_list in parsers_to_run.items():
            if parser_list:
                self.log.debug(f'Running the following under the {framework} framework with YARA: {parser_names}')
                results[framework] = self.FRAMEWORK_LIBRARY_MAPPING[framework].run(sample, parser_list)

        return results
