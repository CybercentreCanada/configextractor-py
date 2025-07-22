"""Base framework class."""

from logging import Logger
from typing import Dict, List, Union

from maco import utils, yara


class Extractor:
    """Represents a configuration extractor module.

    Attributes:
      id (str): Unique identifier for the extractor
      author (str): Author of the extractor
      description (str): Description of the extractor
      sharing (str): Sharing classification of the extractor
      framework (str): Framework the extractor is designed for
      module_path (str): Path to the extractor module
      yara_rule (str): YARA rule for the extractor
      venv (str): Path to the virtual environment for the extractor
    """

    def __init__(self, id, author, description, sharing, framework, module_path, yara_rule, venv=None) -> None:
        """Initialize an Extractor."""
        self.id = id
        self.author = author
        self.description = description
        self.framework = framework
        self.module_path = module_path
        self.rule = yara_rule
        self.sharing = sharing
        self.venv = venv


class Framework:
    """Abstract class for a configuration extractor framework.

    Attributes:
      log (Logger): Logger for the framework
      author_attr_name (str): Name of the author attribute in the extractor module
      description_attr_name (str): Name of the description attribute in the extractor module
      sharing_attr_name (str): Name of the sharing attribute in the extractor module
      yara_attr_name (str): Name of the YARA attribute in the extractor module
      venv_script (str): Script to run the extractor in a virtual environment
      yara_rule (str): YARA rule for the extractor
    """

    def __init__(
        self,
        logger: Logger,
        author_attr_name=None,
        description_attr_name=None,
        sharing_attr_name=None,
        yara_attr_name=None,
    ):
        """Initialize a Framework."""
        self.log = logger
        self.author_attr_name = author_attr_name
        self.description_attr_name = description_attr_name
        self.sharing_attr_name = sharing_attr_name
        self.yara_attr_name = yara_attr_name
        self.venv_script = ""
        self.yara_rule = ""

    @staticmethod
    def get_classification(extractor: Extractor) -> str:
        """Get classification of extractor module.

        Args:
          extractor (Extractor): Extractor module to get the classification of

        Returns:
          (str): The classification of module

        """
        return extractor.sharing

    @staticmethod
    def get_name(extractor: Extractor):
        """Get name of extractor module.

        Args:
          extractor (Extractor): Extractor module to get the name of

        Returns:
          (str): The name of module

        """
        return extractor.id.split(".")[-1]

    # Define a template for results from this Extractor
    def result_template(self, extractor: Extractor, yara_matches: List[yara.Match]) -> Dict[str, str]:
        """A template for results from an extractor.

        Args:
          extractor (Extractor): Extractor module
          yara_matches (List[yara.Match]): YARA matches for the extractor

        Returns:
          (Dict[str, str]): Result template which is the baseline for all results from the extractor under the framework

        """
        return dict(
            author=extractor.author,
            description=extractor.description,
            id=extractor.id,
            yara_hits=[y.rule for y in yara_matches],
        )

    def extract_metadata_from_module(self, decoder: object) -> Dict[str, str]:
        """Extracts metadata from a module.

        Args:
          decoder (object): Module to extract metadata from

        Returns:
          (Dict[str, str]): Metadata extracted from the module

        """
        return {
            "author": self.extract_author(decoder),
            "description": self.extract_description(decoder),
            "sharing": self.extract_sharing(decoder),
            "yara_rule": self.extract_yara(decoder),
        }

    def extract_author(self, decoder: object) -> Union[str, None]:
        """Extract author from module.

        Args:
          decoder (object): Module to extract author from

        Returns:
          (Union[str, None]): Author of the module if found, None otherwise

        """
        if self.author_attr_name and hasattr(decoder, self.author_attr_name):
            # Author information found
            return getattr(decoder, self.author_attr_name)

    def extract_description(self, decoder: object) -> Union[str, None]:
        """Extracts description from module.

        Args:
          decoder (object): Module to extract description from

        Returns:
          (Union[str, None]): Description of the module if found, None otherwise
        """
        if self.description_attr_name and hasattr(decoder, self.description_attr_name):
            # Extractor description found
            return getattr(decoder, self.description_attr_name)

    def extract_sharing(self, decoder: object) -> Union[str, None]:
        """Extract sharing from module.

        Args:
          decoder (object): Module to extract sharing from

        Returns:
          (Union[str, None]): Sharing classification of the module if found, None

        """
        if self.sharing_attr_name and hasattr(decoder, self.sharing_attr_name):
            # Sharing information found
            return getattr(decoder, self.sharing_attr_name)

    def extract_yara(self, decoder: object) -> Union[str, None]:
        """Extract YARA rule from module.

        Args:
          decoder (object): Module to extract YARA rule from

        Returns:
          (Union[str, None]): YARA rule of the module if found, None otherwise

        """
        if self.yara_attr_name and hasattr(decoder, self.yara_attr_name):
            # YARA rule found
            return getattr(decoder, self.yara_attr_name)

    def validate(self, module: object) -> bool:
        """Validate module against framework.

        This method should be implemented by the framework subclass to validate a module belongs to the framework

        Args:
          module (onject): Module to validate
        """
        NotImplementedError()

    def run(self, sample_path: str, parsers: Dict[Extractor, List[yara.Match]], timeout: int) -> List[dict]:
        """Run a series of modules.

        This function should specify how to run a series of modules on a sample under the framework

        Args:
          sample_path (str): Path to the sample to run the modules on
          parsers (Dict[Extractor, List[yara.Match]]): Extractor modules and their YARA matches
          timeout (int): How long to wait for each module to complete

        Returns:
          (List[dict]): List of results from the modules
        """
        return NotImplementedError()

    def run_in_venv(self, sample_path: str, extractor: Extractor) -> Dict[str, dict]:
        """Run an extractor in a virtual environment.

        This function should specify how to run an extractor in a virtual environment.
        By default, it uses the MACO utility to run the extractor as a subprocess.

        Args:
          sample_path (sample_path): Path to the sample to run the extractor on
          extractor (Extractor): Extractor module to run

        Returns:
          (Dict[str, dict]): Results from the extractor

        """
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
