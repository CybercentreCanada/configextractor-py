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
from configextractor.frameworks.base import Extractor, Framework

from logging import getLogger, Logger
from typing import Dict, List, Set

PARSER_FRAMEWORKS = [(MACO, 'yara_rule'), (MWCP, 'yara_rule'), (CAPE, 'rule_source')]

class ConfigExtractor:
    def __init__(self, parsers_dirs: List[str], logger: Logger = None, parser_blocklist: List[str] = []) -> None:
        if not logger:
            logger = getLogger()
        self.log = logger
        self.FRAMEWORK_LIBRARY_MAPPING: Dict[str, Framework] = {fw_cls.__name__: fw_cls(
            logger, yara_attr) for fw_cls, yara_attr in PARSER_FRAMEWORKS}

        self.parsers: Dict[str, Extractor] = dict()
        yara_rules: List[str] = list()
        yara_rule_names: List[str] = list()
        self.standalone_parsers: Dict[str, Set[Extractor]] = defaultdict(set)
        for parsers_dir in parsers_dirs:
            self.log.debug('Adding directories within parser directory in case of local dependencies')
            self.log.debug(f'Adding {os.path.join(parsers_dir, os.pardir)} to PATH')
            not_py = [file for _, _, files in os.walk(parsers_dir) for file in files
                      if not file.endswith('py') and not file.endswith('pyc')]

            # Specific feature for Assemblyline or environments wanting to run parsers from different sources
            # The goal is to try and introduce package isolation/specification similar to a virtual environment when running parsers
            root_venv = None
            if 'venv' in os.listdir(parsers_dir):
                root_venv = os.path.join(parsers_dir, 'venv')

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
            for module_path, module_name, ispkg in pkgutil.walk_packages(mod.__path__, mod.__name__ + "."):

                def find_venv(path: str) -> str:
                    parent_dir = os.path.dirname(path)
                    if parent_dir == parsers_dir or path == parsers_dir:
                        # We made it all the way back to the parser directory
                        # Use root venv, if any
                        return root_venv
                    elif 'venv' in os.listdir(parent_dir):
                        # We found a venv before going back to the root of the parser directory
                        # Assume that because it's the closest, it's the most relevant
                        return os.path.join(parent_dir, 'venv')
                    else:
                        # Keep searching in the parent directory for a venv
                        return find_venv(parent_dir)


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

                # Local site packages, if any, need to be loaded before attempting to import the module
                parser_venv = find_venv(module_path.path)
                parser_site_packages = None
                if parser_venv:
                    for root, dirs, _ in os.walk(parser_venv):
                        if 'site-packages' in dirs:
                            parser_site_packages = os.path.join(root, 'site-packages')
                            sys.path.insert(1, parser_site_packages)
                            break
                try:
                    module = importlib.import_module(module_name)
                except Exception as e:
                    # Log if there was an error importing module
                    self.log.error(f"{module_name}: {e}")
                    continue
                finally:
                    if parser_site_packages in sys.path:
                        sys.path.remove(parser_site_packages)
                # Determine if module contains parsers of a supported framework
                candidates = [module] + [member for _,
                                         member in inspect.getmembers(module) if inspect.isclass(member)]
                for member in candidates:
                    for fw_name, fw_class in self.FRAMEWORK_LIBRARY_MAPPING.items():
                        try:
                            if fw_class.validate(member):
                                if block_regex and block_regex.match(member.__name__):
                                    continue
                                rules = fw_class.extract_yara_from_module(member, module_name, yara_rule_names)
                                ext = Extractor(fw_name, member, module.__file__, parsers_dir, '\n'.join(rules), parser_venv)
                                if not rules:
                                    # Standalone parser, need to know what framework to run under
                                    self.standalone_parsers[fw_name].add(ext)
                                else:
                                    yara_rules.extend(rules)
                                self.parsers[module_name] = ext
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
                for parser_obj in self.parsers.values():
                    parser_obj.module_path = parser_obj.module_path.replace(parsers_dir, original_dir)
                    parser_obj.root_directory = original_dir
                shutil.rmtree(parsers_dir)

        self.yara = yara.compile(source='\n'.join(yara_rules))
        self.log.debug(f"# of YARA-dependent parsers: {len(self.parsers)}")
        self.log.debug(f"# of YARA rules extracted from parsers: {len(yara_rules)}")
        [self.log.debug(f"# of standalone {k} parsers: {len(v)}") for k, v in self.standalone_parsers.items()]
        if parser_blocklist:
            self.log.info(f"Ignoring output from the following parsers matching: {parser_blocklist}")

    def get_details(self, extractor: Extractor) -> Dict[str, str]:
        fw_cls = self.FRAMEWORK_LIBRARY_MAPPING[extractor.framework]

        # Extract details about parser
        return {
            'framework': extractor.framework,
            'classification': fw_cls.__class__.get_classification(extractor),
            'name': fw_cls.__class__.get_name(extractor)
        }

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


            # Get YARA-dependent parsers that should run based on match
            for yara_match in self.yara.match(sample_copy.name):
                # Retrieve relevant parser information
                extractor = self.parsers[yara_match.meta.get('parser_module')]
                if block_regex and block_regex.match(extractor.module.__name__):
                    self.log.info(f'Blocking {extractor.module.__name__} based on passed blocklist regex list')
                    continue
                # Pass in yara.Match objects since some framework can leverage it
                parsers_to_run[extractor.framework][extractor].append(yara_match)

            # Add standalone parsers that should run on any file
            for parser_framework, parser_list in self.standalone_parsers.items():
                for parser in parser_list:
                    if block_regex and block_regex.match(parser.module.__name__):
                        self.log.info(f'Blocking {parser.module.__name__} based on passed blocklist regex list')
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
