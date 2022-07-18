import plyara
import yara

from logging import Logger
from plyara.utils import rebuild_yara_rule
from typing import Any, List, Dict


class Framework():
    def __init__(self, logger: Logger, yara_attr_name=None):
        self.log = logger
        self.yara_attr_name = yara_attr_name

    @staticmethod
    # Get classification of module
    def get_classification(module: Any) -> str:
        return None

    @staticmethod
    # Get name of module
    def get_name(module):
        return module.__name__.split('.')[-1]

    # Extract YARA rules from module
    def extract_yara_from_module(self, decoder: object, parser_path: str) -> List[str]:
        if self.yara_attr_name and hasattr(decoder, self.yara_attr_name):
            yara_rules = list()
            # Modify YARA rule to include meta about the parser
            yara_parser = plyara.Plyara()
            for yara_rule_frag in yara_parser.parse_string(getattr(decoder, self.yara_attr_name)):

                # If this rule came with no metadata then instantiate it
                if not yara_rule_frag.get('metadata'):
                    yara_rule_frag['metadata'] = list()
                yara_rule_frag['metadata'].extend([{'parser_path': parser_path},
                                                   {'parser_framework': self.__class__.__name__.upper()},
                                                   {'parser_name': decoder.__name__}])

                # TODO - Modify the name of the rule to avoid duplicate identifiers during compilation
                rebuilt_rule = rebuild_yara_rule(yara_rule_frag)
                try:
                    yara.compile(source=rebuilt_rule)
                    yara_rules.append(rebuilt_rule)
                except Exception as e:
                    self.log.error(f"{parser_path}: {e}")
            return yara_rules

    # Validate module against framework
    def validate(self, module: Any) -> bool:
        NotImplementedError()

    # Run a series of modules
    def run(self, sample_path: str, parsers: Dict[Any, List[yara.Match]]) -> Dict[str, dict]:
        return NotImplementedError()
