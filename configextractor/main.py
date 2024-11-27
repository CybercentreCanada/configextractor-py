# Main module for ConfigExtractor library
import inspect
import re as regex
import tempfile
from collections import defaultdict
from logging import Logger, getLogger
from multiprocessing import Manager, Process
from multiprocessing.managers import ListProxy
from traceback import format_exc
from types import ModuleType
from typing import Callable, Dict, List
from urllib.parse import urlparse

import cart
from maco import utils, yara

from configextractor.frameworks import MACO, MWCP
from configextractor.frameworks.base import Extractor, Framework


def import_extractors(
    root_directory: str,
    scanner: yara.Rules,
    extractor_module_callback: Callable[[ModuleType, str], None],
    logger: Logger,
    create_venv: bool,
    exceptions: ListProxy,
):
    try:
        utils.import_extractors(root_directory, scanner, extractor_module_callback, logger, create_venv)
    except Exception:
        exceptions.append(format_exc())


class ConfigExtractor:
    def __init__(
        self,
        parsers_dirs: List[str],
        logger: Logger = None,
        parser_blocklist: List[str] = [],
        create_venv: bool = False,
        framework_classes: List[Framework] = [MACO, MWCP],
    ) -> None:
        if not logger:
            logger = getLogger()
        self.log = logger
        self.FRAMEWORK_LIBRARY_MAPPING: Dict[str, Framework] = {
            fw_cls.__name__: fw_cls(self.log) for fw_cls in framework_classes
        }

        self.parsers: Dict[str, Extractor] = dict()
        block_regex = regex.compile("|".join(parser_blocklist)) if parser_blocklist else None
        scanner = yara.compile("\n".join([fw_class.yara_rule for fw_class in self.FRAMEWORK_LIBRARY_MAPPING.values()]))
        with Manager() as manager:
            parsers = manager.dict()
            exceptions = manager.list()

            def extractor_module_callback(module, venv):
                # Check to see if we're blocking this potential extractor
                for fw_name, fw_class in self.FRAMEWORK_LIBRARY_MAPPING.items():
                    members = inspect.getmembers(module, predicate=fw_class.validate)
                    for _, member in members:
                        module_id = module.__name__
                        if member.__name__ != module.__name__:
                            # Account for the possibility of multiple extractor classes within the same module
                            module_id = f"{module.__name__}.{member.__name__}"

                        class_name = module_id.rsplit(".", 1)[1]
                        with open(module.__file__, "r") as fp:
                            if f"class {class_name}" not in fp.read():
                                # Class found is not in this file
                                continue

                        if module_id.startswith("src."):
                            # Cleanup `src` from module_id
                            module_id = module_id[4:]

                        if block_regex and block_regex.match(module_id):
                            return

                        parsers[module_id] = dict(
                            id=module_id,
                            framework=fw_name,
                            module_path=module.__file__,
                            venv=venv,
                            **fw_class.extract_metadata_from_module(member),
                        )

            # Launch importing extractors as separate processes
            processes = []
            for parsers_dir in parsers_dirs:
                p = Process(
                    target=import_extractors,
                    args=(parsers_dir, scanner, extractor_module_callback, logger, create_venv, exceptions),
                )
                processes.append(p)
                p.start()

            # Wait for all the processes to terminate
            for p in processes:
                p.join()

            exceptions = list(exceptions)
            if exceptions:
                raise Exception(f"Exception occurred while importing extractors: {exceptions}")

            self.parsers = {id: Extractor(**extractor_kwargs) for id, extractor_kwargs in dict(parsers).items()}

        self.yara = yara.compile(
            sources={name: extractor.rule for name, extractor in self.parsers.items() if extractor.rule}
        )
        for fw_name in self.FRAMEWORK_LIBRARY_MAPPING:
            self.log.debug(
                f"# of YARA-dependent parsers under {fw_name}: "
                f"{len([p for p in self.parsers.values() if p.rule and p.framework == fw_name])}"
            )
            self.log.debug(
                f"# of YARA-independent parsers under {fw_name}: "
                f"{len([p for p in self.parsers.values() if not p.rule and p.framework == fw_name])}"
            )
        if parser_blocklist:
            self.log.info(f"Ignoring output from the following parsers matching: {parser_blocklist}")

    def get_details(self, extractor: Extractor) -> Dict[str, str]:
        fw_cls = self.FRAMEWORK_LIBRARY_MAPPING[extractor.framework]

        # Extract details about parser
        return {
            "framework": extractor.framework,
            "classification": fw_cls.__class__.get_classification(extractor),
            "name": fw_cls.__class__.get_name(extractor),
            "path": extractor.module_path,
            "id": extractor.id,
        }

    def finalize(self, results: List[dict]):
        # Ensure schemes/protocol are present in HTTP configurations
        for config in results:
            config = config.get("config", {})
            for network_conn in config.get("http", []):
                network_conn.setdefault("protocol", "http")
                # Ensure protocol is lowercased
                network_conn["protocol"] = network_conn["protocol"].lower()
                uri: str = network_conn.get("uri")
                if uri and not uri.startswith(network_conn["protocol"]):
                    # Ensure URI starts with protocol
                    network_conn["uri"] = f"{network_conn['protocol']}://{uri}"
                # Parse the URI and fill in missing sections where possible
                parsed_uri = urlparse(uri)
                for part in ["username", "password", "hostname", "port", "path", "query", "fragment"]:
                    value = network_conn.get(part, getattr(parsed_uri, part))
                    if value:
                        network_conn[part] = value

    def run_parsers(self, sample, parser_blocklist=[]):
        results = dict()
        parsers_to_run = defaultdict(lambda: defaultdict(list))
        block_regex = regex.compile("|".join(parser_blocklist)) if parser_blocklist else None

        with tempfile.NamedTemporaryFile() as sample_copy:
            # Make a copy of the sample that will be cleaned up after analysis is complete
            with open(sample, "rb") as fp:
                buf = fp.read()

            if cart.is_cart(buf):
                # Uncart file to temporary location for analysis
                cart.unpack_file(sample, sample_copy.name)
            else:
                # Make a copy of the file to the temporary location
                sample_copy.write(buf)
                sample_copy.flush()

            # Get YARA-dependent parsers that should run based on match
            for yara_match in self.yara.match(sample_copy.name):
                # Retrieve relevant parser information
                extractor = self.parsers[yara_match.namespace]
                if block_regex and block_regex.match(extractor.id):
                    self.log.info(f"Blocking {extractor.id} based on passed blocklist regex list")
                    continue
                # Pass in yara.Match objects since some framework can leverage it
                parsers_to_run[extractor.framework][extractor].append(yara_match)

            # Add standalone parsers that should run on any file
            for parser in [p for p in self.parsers.values() if not p.rule]:
                if block_regex and block_regex.match(parser.id):
                    self.log.info(f"Blocking {parser.id} based on passed blocklist regex list")
                    continue
                parsers_to_run[parser.framework][parser].extend([])

            for framework, parser_list in parsers_to_run.items():
                if parser_list:
                    self.log.debug(
                        f"Running the following under the {framework} framework with YARA: {[p.id for p in parser_list]}"
                    )
                    result = self.FRAMEWORK_LIBRARY_MAPPING[framework].run(sample_copy.name, parser_list)
                    self.finalize(result)
                    if result:
                        results[framework] = result

        return results
