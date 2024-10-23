import inspect
import json
from base64 import b64decode
from logging import Logger
from typing import Any, Dict, List, Union

from maco.extractor import Extractor as MACO_Extractor
from maco.model import ExtractorModel
from maco.utils import VENV_SCRIPT as MACO_VENV_SCRIPT, maco_extractor_validation

from configextractor.frameworks.base import Extractor, Framework


class Base64Decoder(json.JSONDecoder):
    def __init__(self, *args, **kwargs):
        json.JSONDecoder.__init__(self, object_hook=self.object_hook, *args, **kwargs)

    def object_hook(self, obj):
        if "__class__" not in obj:
            return obj
        type = obj["__class__"]
        if type == "bytes":
            return b64decode(obj["data"])
        return obj


class MACO(Framework):
    def __init__(self, logger: Logger, yara_attr_name=None):
        super().__init__(logger, yara_attr_name)
        self.venv_script = MACO_VENV_SCRIPT

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
