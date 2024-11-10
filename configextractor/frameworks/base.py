from logging import Logger
from typing import Any, Dict, List

from maco import utils, yara


class Extractor:
    def __init__(self, id, framework, module, module_path, root_directory, yara_rule, venv=None) -> None:
        self.id = id
        self.framework = framework
        self.module = module
        self.module_path = module_path
        self.root_directory = root_directory
        self.rule = yara_rule
        self.venv = venv


class Framework:
    def __init__(self, logger: Logger, yara_attr_name=None):
        self.log = logger
        self.yara_attr_name = yara_attr_name
        self.venv_script = ""
        self.yara_rule = ""

    @staticmethod
    # Get classification of module
    def get_classification(extractor: Extractor) -> str:
        return None

    @staticmethod
    # Get name of module
    def get_name(extractor: Extractor):
        return extractor.module.__name__.split(".")[-1]

    # Define a template for results from this Extractor
    def result_template(self, extractor: Extractor, yara_matches: List[yara.Match]) -> Dict[str, str]:
        return dict(id=extractor.id, yara_hits=[y.rule for y in yara_matches])

    # Extract YARA rules from module
    def extract_yara_from_module(self, decoder: object) -> str:
        if self.yara_attr_name and hasattr(decoder, self.yara_attr_name):
            # YARA rule found
            return getattr(decoder, self.yara_attr_name)

    # Validate module against framework
    def validate(self, module: Any) -> bool:
        NotImplementedError()

    # Run a series of modules
    def run(self, sample_path: str, parsers: Dict[Extractor, List[yara.Match]]) -> List[dict]:
        return NotImplementedError()

    def run_in_venv(self, sample_path: str, extractor: Extractor) -> Dict[str, dict]:
        # Run in extractor with sample in virtual enviroment using the MACO utility
        return utils.run_in_venv(
            sample_path,
            extractor.module,
            extractor.module_path,
            extractor.venv,
            self.venv_script,
            json_decoder=None,
        )
