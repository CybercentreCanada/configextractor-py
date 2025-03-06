import json
from logging import Logger
from typing import Dict, List, Union

from maco.exceptions import AnalysisAbortedException
from maco.model import ExtractorModel
from maco.utils import MACO_YARA_RULE
from maco.utils import VENV_SCRIPT as MACO_VENV_SCRIPT
from maco.utils import Base64Decoder, maco_extractor_validation

from configextractor.frameworks.base import Extractor, Framework


class MACO(Framework):
    """MACO framework for configuration extraction"""

    def __init__(self, logger: Logger):
        super().__init__(logger, "author", "__doc__", "sharing", "yara_rule")
        self.venv_script = MACO_VENV_SCRIPT
        self.yara_rule = MACO_YARA_RULE

    def validate(self, module: object) -> bool:
        """Validate the extractor module using MACO's validation function

        Args:
          module (object): Extractor module

        Returns:
            True if the module is valid, False otherwise

        """
        return maco_extractor_validation(module)

    def run(self, sample_path: str, parsers: Dict[Extractor, List[str]]) -> List[dict]:
        """Run extractors from the MACO framework on the sample

        Args:
          sample_path (str): Path to the sample to run the modules on
          parsers (Dict[Extractor, List[str]]): Extractor modules and their YARA matches

        Returns:
            List of results from the modules
        """
        results = list()
        for extractor, yara_matches in parsers.items():
            try:
                result = self.result_template(extractor, yara_matches)

                # Run MaCo parser with YARA matches
                r: ExtractorModel = self.run_in_venv(sample_path, extractor)

                if not (r or yara_matches):
                    # Nothing to report
                    continue
                if r:
                    result.update({"config": r.dict(exclude_defaults=True, exclude_none=True)})

            except AnalysisAbortedException:
                # Extractor voluntarily aborted extraction
                # This is the equivalent of the sample being invalid for the extractor
                continue

            except Exception as e:
                # Add exception to results
                result["exception"] = str(e)
                self.log.error(f"{extractor.id}: {e}")
            results.append(result)
        return results

    def run_in_venv(self, sample_path: str, extractor: Extractor) -> Union[ExtractorModel, None]:
        """Run an extractor in a virtual environment

        Args:
          sample_path (str): Path to the sample to run the extractor on
          extractor (Extractor): Extractor module to run

        Returns:
            Results from the extractor using MACO model, None if no results
        """
        # Load results and apply them against the model
        result = json.loads(json.dumps(super().run_in_venv(sample_path, extractor)), cls=Base64Decoder)
        return ExtractorModel(**result) if result else None
