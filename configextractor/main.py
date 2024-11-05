# Main module for ConfigExtractor library
import cart
import os
import regex
import tempfile
import yara

from collections import defaultdict
from logging import Logger, getLogger
from maco import utils
from typing import Dict, List
from urllib.parse import urlparse

from configextractor.frameworks import MACO, MWCP
from configextractor.frameworks.base import Extractor, Framework

PARSER_FRAMEWORKS = [(MACO, "yara_rule"), (MWCP, "yara_rule")]


class ConfigExtractor:
    def __init__(
        self,
        parsers_dirs: List[str],
        logger: Logger = None,
        parser_blocklist: List[str] = [],
        create_venv: bool = False,
    ) -> None:
        if not logger:
            logger = getLogger()
        self.log = logger
        self.FRAMEWORK_LIBRARY_MAPPING: Dict[str, Framework] = {
            fw_cls.__name__: fw_cls(self.log, yara_attr) for fw_cls, yara_attr in PARSER_FRAMEWORKS
        }

        self.parsers: Dict[str, Extractor] = dict()
        namespaced_yara_rules: Dict[str, List[str]] = dict()
        block_regex = regex.compile("|".join(parser_blocklist)) if parser_blocklist else None
        for parsers_dir in parsers_dirs:
            if create_venv:
                # Recursively create/update virtual environments
                utils.create_venv(parsers_dir, logger=self.log)

            def extractor_module_callback(member, module, venv):
                # Check to see if we're blocking this potential extractor
                if block_regex and block_regex.match(member.__name__):
                    return

                for fw_name, fw_class in self.FRAMEWORK_LIBRARY_MAPPING.items():
                    if fw_class.validate(member):
                        # Positively identified extractor that belongs to supported framework
                        module_id = module.__name__
                        if member.__name__ != module.__name__:
                            # Account for the possibility of multiple extractor classes within the same module
                            module_id = f"{module.__name__}.{member.__name__}"

                        rules = "\n".join(fw_class.extract_yara_from_module(member)) or None
                        if rules:
                            namespaced_yara_rules[module_id] = rules

                        module_root = module_id.split(".", 1)[0]
                        parsers_dir_name = os.path.basename(parsers_dir)
                        if module_root != parsers_dir_name:
                            # MACO has loaded the module from a temporary directory
                            # Repair the ID of the extractor to be relative to the original directory
                            module_id = module_id.replace(module_root, parsers_dir_name, 1)

                        self.parsers[module_id] = Extractor(
                            module_id,
                            fw_name,
                            member,
                            module.__file__,
                            parsers_dir,
                            rules,
                            venv,
                        )
                        return True

            utils.find_extractors(
                parsers_dir,
                logger=self.log,
                extractor_module_callback=extractor_module_callback,
            )

        self.yara = yara.compile(sources={ns: rules for ns, rules in namespaced_yara_rules.items()})
        for fw_name in list(self.FRAMEWORK_LIBRARY_MAPPING.keys()):
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
                if block_regex and block_regex.match(extractor.module.__name__):
                    self.log.info(f"Blocking {extractor.module.__name__} based on passed blocklist regex list")
                    continue
                # Pass in yara.Match objects since some framework can leverage it
                parsers_to_run[extractor.framework][extractor].append(yara_match)

            # Add standalone parsers that should run on any file
            for parser in [p for p in self.parsers.values() if not p.rule]:
                if block_regex and block_regex.match(parser.module.__name__):
                    self.log.info(f"Blocking {parser.module.__name__} based on passed blocklist regex list")
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
