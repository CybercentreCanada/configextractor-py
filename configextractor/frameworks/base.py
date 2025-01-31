from logging import Logger
from typing import Any, Dict, List

from maco import utils, yara


class Extractor:
    def __init__(self, id, author, description, sharing, framework, module_path, yara_rule, venv=None) -> None:
        self.id = id
        self.author = author
        self.description = description
        self.framework = framework
        self.module_path = module_path
        self.rule = yara_rule
        self.sharing = sharing
        self.venv = venv


class Framework:
    def __init__(
        self,
        logger: Logger,
        author_attr_name=None,
        description_attr_name=None,
        sharing_attr_name=None,
        yara_attr_name=None,
    ):
        self.log = logger
        self.author_attr_name = author_attr_name
        self.description_attr_name = description_attr_name
        self.sharing_attr_name = sharing_attr_name
        self.yara_attr_name = yara_attr_name
        self.venv_script = ""
        self.yara_rule = ""

    @staticmethod
    # Get classification of module
    def get_classification(extractor: Extractor) -> str:
        return extractor.sharing

    @staticmethod
    # Get name of module
    def get_name(extractor: Extractor):
        return extractor.id.split(".")[-1]

    # Define a template for results from this Extractor
    def result_template(self, extractor: Extractor, yara_matches: List[yara.Match]) -> Dict[str, str]:
        return dict(
            author=extractor.author,
            description=extractor.description,
            id=extractor.id,
            yara_hits=[y.rule for y in yara_matches],
        )

    def extract_metadata_from_module(self, decoder: object) -> Dict[str, str]:
        return {
            "author": self.extract_author(decoder),
            "description": self.extract_description(decoder),
            "sharing": self.extract_sharing(decoder),
            "yara_rule": self.extract_yara(decoder),
        }

    # Extract author from module
    def extract_author(self, decoder: object) -> str:
        if self.author_attr_name and hasattr(decoder, self.author_attr_name):
            # Author information found
            return getattr(decoder, self.author_attr_name)

    # Extract description from module
    def extract_description(self, decoder: object) -> str:
        if self.description_attr_name and hasattr(decoder, self.description_attr_name):
            # Extractor description found
            return getattr(decoder, self.description_attr_name)

    # Extract sharing from module
    def extract_sharing(self, decoder: object) -> str:
        if self.sharing_attr_name and hasattr(decoder, self.sharing_attr_name):
            # Sharing information found
            return getattr(decoder, self.sharing_attr_name)

    # Extract YARA rules from module
    def extract_yara(self, decoder: object) -> str:
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
        module_name, extractor_class = extractor.id.rsplit(".", 1)
        output = utils.run_extractor(
            sample_path,
            module_name,
            extractor_class,
            extractor.module_path,
            extractor.venv,
            self.venv_script,
            json_decoder=None,
        )

        if not isinstance(output, dict):
            output = output.model_dump(exclude_none=True, exclude_defaults=True)

        return output
