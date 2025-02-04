import json
from logging import Logger
from typing import Any, Dict, List, Union

from maco.model import ExtractorModel
from maco.utils import MACO_YARA_RULE, Base64Decoder, maco_extractor_validation
from maco.utils import VENV_SCRIPT as MACO_VENV_SCRIPT
from maco.exceptions import AnalysisAbortedException

from configextractor.frameworks.base import Extractor, Framework


class MACO(Framework):
    def __init__(self, logger: Logger):
        super().__init__(logger, "author", "__doc__", "sharing", "yara_rule")
        self.venv_script = MACO_VENV_SCRIPT
        self.yara_rule = MACO_YARA_RULE

    def validate(self, module: Any) -> bool:
        return maco_extractor_validation(module)

    def run(self, sample_path: str, parsers: Dict[Extractor, List[str]]) -> List[dict]:
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
        # Load results and apply them against the model
        result = json.loads(json.dumps(super().run_in_venv(sample_path, extractor)), cls=Base64Decoder)
        return ExtractorModel(**result) if result else None
