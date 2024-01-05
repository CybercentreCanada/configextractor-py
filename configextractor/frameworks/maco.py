import inspect
import json
from base64 import b64decode
from logging import Logger
from typing import Any, Dict, List, Union

from maco.extractor import Extractor as MACO_Extractor
from maco.model import ExtractorModel

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
        self.venv_script = """
import importlib
import json
import os
import sys
import yara

from base64 import b64encode
parent_package_path = os.path.dirname(__file__).rsplit("{module_name}".split('.', 1)[0], 1)[0]
sys.path.insert(1, parent_package_path)
mod = importlib.import_module("{module_name}")

class Base64Encoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, bytes):
            return dict(__class__="bytes", data=b64encode(o).decode())
        return json.JSONEncoder.default(self, o)

result = mod.{module_class}().run(open("{sample_path}", 'rb'), matches=yara.compile(source=mod.{module_class}.yara_rule).match("{sample_path}"))

with open("{output_path}", 'w') as fp:
    if not result:
        json.dump(dict(), fp)
    else:
        try:
            json.dump(result.model_dump(exclude_defaults=True, exclude_none=True), fp, cls=Base64Encoder)
        except AttributeError:
            # venv likely has an older version of Pydantic < 2 installed
            json.dump(result.dict(exclude_defaults=True, exclude_none=True), fp, cls=Base64Encoder)
"""

    @staticmethod
    def get_classification(extractor: Extractor):
        if hasattr(extractor.module, "sharing"):
            return extractor.module.sharing

    def validate(self, module: Any) -> bool:
        if inspect.isclass(module):
            # 'author' has to be implemented otherwise will raise an exception according to MACO
            return bool(issubclass(module, MACO_Extractor) and module.author)
        return False

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

    def run_in_venv(self, sample_path: str, extractor: Extractor) -> Union[ExtractorModel, None]:
        # Load results and apply them against the model
        result = json.loads(json.dumps(super().run_in_venv(sample_path, extractor)), cls=Base64Decoder)
        for b in result.get("binaries", []):
            if b.get("data"):
                # Decode base64-encoded binaries
                b["data"] = b64decode(b["data"])
        return ExtractorModel(**result) if result else None
