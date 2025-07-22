"""MACO Framework."""

import json
from logging import Logger
from multiprocessing import Manager, Process
from typing import Dict, List, Union

from maco.exceptions import AnalysisAbortedException
from maco.model import ExtractorModel
from maco.utils import MACO_YARA_RULE, Base64Decoder, maco_extractor_validation
from maco.utils import VENV_SCRIPT as MACO_VENV_SCRIPT

from configextractor.frameworks.base import Extractor, Framework


class MACO(Framework):
    """MACO framework for configuration extraction."""

    def __init__(self, logger: Logger):
        """Initialize the MACO framework.

        Args:
          logger (Logger): Logger to use
        """
        super().__init__(logger, "author", "__doc__", "sharing", "yara_rule")
        self.venv_script = MACO_VENV_SCRIPT
        self.yara_rule = MACO_YARA_RULE

    def validate(self, module: object) -> bool:
        """Validate the extractor module using MACO's validation function.

        Args:
          module (object): Extractor module

        Returns:
            (bool): True if the module is valid, False otherwise

        """
        return maco_extractor_validation(module)

    def run(self, sample_path: str, parsers: Dict[Extractor, List[str]], timeout: int) -> List[dict]:
        """Run extractors from the MACO framework on the sample.

        Args:
          sample_path (str): Path to the sample to run the modules on
          parsers (Dict[Extractor, List[str]]): Extractor modules and their YARA matches
          timeout (int): How long to wait for the extractor to finish

        Returns:
            (List[dict]): List of results from the modules
        """
        with Manager() as manager:
            results = manager.list()

            def run_extractor(extractor: Extractor, yara_matches: List[str], results: List[Dict]) -> None:
                """Run a single extractor and return the result."""
                try:
                    result = self.result_template(extractor, yara_matches)

                    # Run MaCo parser with YARA matches
                    r: ExtractorModel = self.run_in_venv(sample_path, extractor)

                    if not (r or yara_matches):
                        # Nothing to report
                        return
                    if r:
                        result.update({"config": r.dict(exclude_defaults=True, exclude_none=True)})

                except AnalysisAbortedException:
                    # Extractor voluntarily aborted extraction
                    # This is the equivalent of the sample being invalid for the extractor
                    return

                except Exception as e:
                    # Add exception to results
                    result["exception"] = str(e)
                    self.log.error(f"{extractor.id}: {e}")
                results.append(result)

            processes = []
            for extractor, yara_matches in parsers.items():
                p = Process(
                    target=run_extractor,
                    args=(extractor, yara_matches, results),
                )
                p.start()
                processes.append(p)

            # Wait for all processes to finish
            for p in processes:
                p.join(timeout)

            return list(results)

    def run_in_venv(self, sample_path: str, extractor: Extractor) -> Union[ExtractorModel, None]:
        """Run an extractor in a virtual environment.

        Args:
          sample_path (str): Path to the sample to run the extractor on
          extractor (Extractor): Extractor module to run

        Returns:
            (Union[ExtractorModel, None]): Results from the extractor using MACO model, None if no results
        """
        # Load results and apply them against the model
        result = json.loads(json.dumps(super().run_in_venv(sample_path, extractor)), cls=Base64Decoder)
        return ExtractorModel(**result) if result else None
