import json
from logging import Logger
from typing import Any, Dict, List, Union

from maco.model import ExtractorModel
from maco.utils import VENV_SCRIPT as MACO_VENV_SCRIPT, maco_extractor_validation, Base64Decoder, MACO_YARA_RULE

from configextractor.frameworks.base import Extractor, Framework


class MACO(Framework):
    def __init__(self, logger: Logger):
        super().__init__(logger, "yara_rule")
        self.venv_script = MACO_VENV_SCRIPT
        self.yara_rule = MACO_YARA_RULE

    @staticmethod
    def get_classification(extractor: Extractor):
        if hasattr(extractor.module, "sharing"):
            return extractor.module.sharing

    def validate(self, module: Any) -> bool:
        return maco_extractor_validation(module)

    def result_template(self, extractor: Extractor, yara_matches: List) -> Dict[str, str]:
        template = super().result_template(extractor, yara_matches)
        decoder = extractor.module()
        template.update(
            {
                "author": decoder.author,
                "description": decoder.__doc__,
            }
        )
        return template

    def run(self, sample_path: str, parsers: Dict[Extractor, List[str]]) -> List[dict]:
        results = list()
        for extractor, yara_matches in parsers.items():
            try:
                decoder = extractor.module()
                result = self.result_template(extractor, yara_matches)

                # Run MaCo parser with YARA matches
                r: ExtractorModel = None
                if extractor.venv:
                    # Run in special mode using the virtual environment detected
                    r = self.run_in_venv(sample_path, extractor)
                else:
                    r = decoder.run(open(sample_path, "rb"), matches=yara_matches)

                if not (r or yara_matches):
                    # Nothing to report
                    continue
                if r:
                    result.update({"config": r.dict(exclude_defaults=True, exclude_none=True)})

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
