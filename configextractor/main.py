# Main module for ConfigExtractor library
import cart
import importlib
import inspect
import os
import pkgutil
import regex
import shutil
import sys
import tempfile
import yara

from collections import defaultdict
from configextractor.frameworks import CAPE, MACO, MWCP

from logging import getLogger, Logger
from typing import Dict, List

PARSER_FRAMEWORKS = [(MACO, 'yara_rule'), (MWCP, 'yara_rule'), (CAPE, 'rule_source')]


class ConfigExtractor:
    def __init__(self, parsers_dirs: list, logger: Logger = None, parser_blocklist=[]) -> None:
        if not logger:
            logger = getLogger()
        self.log = logger
        self.FRAMEWORK_LIBRARY_MAPPING = {fw_cls.__name__: fw_cls(
            logger, yara_attr) for fw_cls, yara_attr in PARSER_FRAMEWORKS}

        self.parsers = dict()
        yara_rules = list()
        yara_rule_names = list()
        self.standalone_parsers = defaultdict(set)
        for parsers_dir in parsers_dirs:
            self.log.debug('Adding directories within parser directory in case of local dependencies')
            self.log.debug(f'Adding {os.path.join(parsers_dir, os.pardir)} to PATH')
            not_py = [file for _, _, files in os.walk(parsers_dir) for file in files
                      if not file.endswith('py') and not file.endswith('pyc')]

            # Find extractors (taken from MaCo's Collector class)
            path_parent, foldername = os.path.split(parsers_dir)
            original_dir = parsers_dir
            sys.path.insert(1, path_parent)
            sys.path.insert(1, parsers_dir)
            mod = importlib.import_module(foldername)

            if mod.__file__ and not mod.__file__.startswith(parsers_dir):
                # Library confused folder name with installed package
                sys.path.remove(path_parent)
                sys.path.remove(parsers_dir)
                parsers_dir = tempfile.TemporaryDirectory().name
                shutil.copytree(original_dir, parsers_dir, dirs_exist_ok=True)

                path_parent, foldername = os.path.split(parsers_dir)
                sys.path.insert(1, path_parent)
                sys.path.insert(1, parsers_dir)
                mod = importlib.import_module(foldername)

            # walk packages in the extractors directory to find all extactors
            block_regex = regex.compile('|'.join(parser_blocklist)) if parser_blocklist else None
            for _, module_name, ispkg in pkgutil.walk_packages(mod.__path__, mod.__name__ + "."):
                if ispkg:
                    # skip __init__.py
                    continue

                if module_name.endswith('.setup'):
                    # skip setup.py
                    continue

                if any([module_name.split('.')[-1] in np for np in not_py]):
                    # skip non-Python files
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
                candidates = [module] + [member for _,
                                         member in inspect.getmembers(module) if inspect.isclass(member)]
                for member in candidates:
                    for fw_name, fw_class in self.FRAMEWORK_LIBRARY_MAPPING.items():
                        try:
                            if fw_class.validate(member):
                                if block_regex and block_regex.match(member.__name__):
                                    continue
                                self.parsers[module.__file__] = member
                                rules = fw_class.extract_yara_from_module(member, module.__file__, yara_rule_names)
                                if not rules:
                                    # Standalone parser, need to know what framework to run under
                                    self.standalone_parsers[fw_name].add(member)
                                else:
                                    yara_rules.extend(rules)
                                break
                        except TypeError:
                            pass
                        except Exception as e:
                            self.log.error(f"{member}: {e}")

                # Correct metadata in YARA rules
                if original_dir != parsers_dir:
                    yara_rules = [rule.replace(parsers_dir, original_dir) for rule in yara_rules]

            if original_dir != parsers_dir:
                # Correct the paths to the parsers to match metadata changes
                sys.path.remove(path_parent)
                sys.path.remove(parsers_dir)
                path_parent, _ = os.path.split(original_dir)
                sys.path.insert(1, path_parent)
                sys.path.insert(1, original_dir)
                self.parsers = {k.replace(parsers_dir, original_dir): v for k, v in self.parsers.items()}
                shutil.rmtree(parsers_dir)

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
                    'classification': fw_class.__class__.get_classification(module),
                    'name': fw_class.__class__.get_name(module)
                }
        return None

    def finalize(self, results: List[dict]):
        # Ensure schemes/protocol are present in HTTP configurations
        for config in results.values():
            config = config.get('config', {})
            for network_conn in config.get('http', []):
                network_conn.setdefault('protocol', 'http')
                uri: str = network_conn.get('uri')
                if uri and not uri.startswith(network_conn['protocol']):
                    # Ensure URI starts with protocol
                    network_conn['uri'] = f"{network_conn['protocol']}://{uri}"

    def run_parsers(self, sample, parser_blocklist=[]):
        results = dict()
        parsers_to_run = defaultdict(lambda: defaultdict(list))
        parser_names = list()
        block_regex = regex.compile('|'.join(parser_blocklist)) if parser_blocklist else None

        with tempfile.NamedTemporaryFile() as sample_copy:
            # Make a copy of the sample that will be cleaned up after analysis is complete
            with open(sample, 'rb') as fp:
                buf = fp.read()

            if cart.is_cart(buf):
                # Uncart file to temporary location for analysis
                cart.unpack_file(sample, sample_copy.name)
            else:
                # Make a copy of the file to the temporary location
                sample_copy.write(buf)


            # Get YARA-dependents parsers that should run based on match
            for yara_match in self.yara.match(sample_copy.name):
                # Retrieve relevant parser information
                parser_path = yara_match.meta.get('parser_path')
                parser_framework = yara_match.meta.get('parser_framework')
                parser_names.append(yara_match.meta.get('parser_name'))

                parser_module = self.parsers[parser_path]
                if block_regex and block_regex.match(parser_module.__name__):
                    self.log.info(f'Blocking {parser_module.__name__} based on passed blocklist regex list')
                    continue
                # Pass in yara.Match objects since some framework can leverage it
                parsers_to_run[parser_framework][parser_module].append(yara_match)

            # Add standalone parsers that should run on any file
            for parser_framework, parser_list in self.standalone_parsers.items():
                for parser in parser_list:
                    if block_regex and block_regex.match(parser.__name__):
                        self.log.info(f'Blocking {parser.__name__} based on passed blocklist regex list')
                        continue
                    parsers_to_run[parser_framework][parser].extend([])

            for framework, parser_list in parsers_to_run.items():
                if parser_list:
                    self.log.debug(f'Running the following under the {framework} framework with YARA: {parser_names}')
                    result = self.FRAMEWORK_LIBRARY_MAPPING[framework].run(sample_copy.name, parser_list)
                    self.finalize(result)
                    if result:
                        results[framework] = result

        return results
