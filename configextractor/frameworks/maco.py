import inspect
from base64 import b64decode
from logging import Logger
from typing import Any, Dict, List

from maco.extractor import Extractor as MACO_Extractor
from maco.model import ExtractorModel

from configextractor.frameworks.base import Extractor, Framework


class MACO(Framework):
    def __init__(self, logger: Logger, yara_attr_name=None):
        super().__init__(logger, yara_attr_name)
        self.venv_script = """
import json
import yara
from base64 import b64encode
from .{module_name} import {module_class}

class Base64Encoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, bytes):
            return b64encode(o).decode()
        return json.JSONEncoder.default(self, o)

result = {module_class}().run(open("{sample_path}", 'rb'), matches=yara.compile("{yara_rule}").match("{sample_path}"))
with open("{output_path}", 'w') as fp:
    json.dump(result.dict(exclude_defaults=True, exclude_none=True), fp, cls=Base64Encoder)
"""

    @staticmethod
    def get_classification(extractor: Extractor):
        if hasattr(extractor.module, "sharing"):
            return extractor.module.sharing

    def validate(self, module: Any) -> bool:
        if inspect.isclass(module):
            # 'author' has to be implemented otherwise will raise an exception according to MWCP
            return issubclass(module, MACO_Extractor) and module.author

    def result_template(self, extractor: Extractor, yara_matches: List) -> Dict[str, str]:
        template = super().result_template(extractor, yara_matches)
        decoder = extractor.module()
        template.update(
            {
                "author": decoder.author,
                "description": decoder.__doc__,
                "config": {"family": decoder.family if hasattr(decoder, "family") else decoder.__class__.__name__},
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

    def run_in_venv(self, sample_path: str, extractor: Extractor) -> ExtractorModel:
        # Load results and apply them against the model
        result = super().run_in_venv(sample_path, extractor)
        for b in result.get("binaries", []):
            if b.get("data"):
                # Decode base64-encoded binaries
                b["data"] = b64decode(b["data"])
        return ExtractorModel(**result)
