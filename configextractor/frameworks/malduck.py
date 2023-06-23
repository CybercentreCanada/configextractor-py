# MALDUCK framework

import inspect
import os
from logging import Logger
from typing import Any, Dict, List

import plyara
import yara
from malduck import Extractor
from malduck.extractor import ExtractManager, ExtractorModules
from malduck.extractor.extract_manager import Yara
from plyara.utils import rebuild_yara_rule

from configextractor.frameworks.base import Framework


class CustomYara(Yara):
    def __init__(self, yara_rule_strings: List[str]) -> None:
        self.rules = yara.compile(source="\n".join(yara_rule_strings))


class CustomExtractorModules(ExtractorModules):
    def __init__(self, extractors: List[Any], yara_rule_strings: List[str]) -> None:
        # Save list of modules
        self.extractors = extractors

        # Compile all YARA rules
        self.rules = CustomYara(yara_rule_strings)


class MALDUCK(Framework):
    def __init__(self, logger: Logger, yara_attr_name=None):
        super().__init__(logger, yara_attr_name)
        self.rule_map = dict()

    def validate(self, module: Any) -> bool:
        if inspect.isclass(module) and not module == Extractor:
            return issubclass(module, Extractor)

    # Extract YARA rules from module
    def extract_yara_from_module(self, decoder: object, parser_path: str, existing_rule_names=[]) -> List[str]:
        if self.yara_attr_name and hasattr(decoder, self.yara_attr_name) and getattr(decoder, self.yara_attr_name):
            yara_rules = list()
            # The attribute contains a list of YARA rule names, therefore we need to inspect the immediate directory for matching rules
            for root, _, files in os.walk(os.path.dirname(parser_path)):
                for file in files:
                    filepath = os.path.join(root, file)
                    try:
                        yara.compile(filepath)
                    except yara.SyntaxError:
                        # Ignore files that don't compile in YARA
                        continue

                    # Modify YARA rule to include meta about the parser
                    yara_parser = plyara.Plyara()
                    for yara_rule_frag in yara_parser.parse_string(open(filepath, "r").read()):
                        # If this rule came with no metadata then instantiate it
                        if not yara_rule_frag.get("metadata"):
                            yara_rule_frag["metadata"] = list()
                        yara_rule_name = yara_rule_frag["rule_name"]
                        yara_rule_frag["metadata"].extend(
                            [
                                {"yara_identifier": yara_rule_name},
                                {"parser_path": parser_path},
                                {"parser_framework": self.__class__.__name__.upper()},
                                {"parser_name": decoder.__name__},
                            ]
                        )

                        # Modify the name of the rule to avoid duplicate identifiers during compilation
                        if yara_rule_name in existing_rule_names:
                            yara_rule_frag[
                                "rule_name"
                            ] = f"{yara_rule_name}_{len([i for i in existing_rule_names if i.startswith(yara_rule_name)])}"

                        existing_rule_names.append(yara_rule_name)
                        rebuilt_rule = rebuild_yara_rule(yara_rule_frag)
                        try:
                            yara.compile(source=rebuilt_rule)
                            yara_rules.append(rebuilt_rule)
                        except Exception as e:
                            self.log.error(f"{parser_path}: {e}")
            self.rule_map[decoder] = yara_rules
            return yara_rules

    def run(self, sample_path: str, parsers: Dict[Any, List[yara.Match]]) -> Dict[str, dict]:
        modules = list(parsers.keys())
        yara_rules = []
        [yara_rules.extend(self.rule_map[m]) for m in modules]
        em = ExtractManager(CustomExtractorModules(modules, yara_rules))
        em.push_file(sample_path)
        # TODO: Convert output to MACO
        return em.configs
