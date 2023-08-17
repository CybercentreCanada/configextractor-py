import inspect
from logging import Logger
import os
import json
import subprocess

from configextractor.frameworks.base import Extractor, Framework
from maco.extractor import Extractor as MACO_Extractor
from maco.model import ExtractorModel

from tempfile import NamedTemporaryFile
from typing import Any, List, Dict


class MACO(Framework):
    def __init__(self, logger: Logger, yara_attr_name=None):
        super().__init__(logger, yara_attr_name)
        self.venv_script = """
import json
import yara
from .{module_name} import {module_class}

result = {module_class}().run(open("{sample_path}", 'rb'), matches=yara.compile("{yara_rule}").match("{sample_path}"))
with open("{output_path}", 'w') as fp:
    json.dump(result.dict(exclude_defaults=True, exclude_none=True), fp)
"""

    @staticmethod
    def get_classification(extractor: Extractor):
        if hasattr(extractor.module, 'sharing'):
            return extractor.module.sharing

    def validate(self, module: Any) -> bool:
        if inspect.isclass(module):
            return issubclass(module, MACO_Extractor)

    def run(self, sample_path: str, parsers: Dict[Extractor, List[str]]) -> Dict[str, dict]:
        results = dict()
        for extractor, yara_matches in parsers.items():
            try:
                decoder: Extractor = extractor.module()
                config = {}
                if hasattr(decoder, 'family') and decoder.family:
                    config['family'] = decoder.family
                else:
                    config['family'] = decoder.__class__.__name__
                # Run MaCo parser with YARA matches
                results[decoder.name] = {
                    "author": decoder.author,
                    "description": decoder.__doc__,
                    "config": config,
                }
                result: ExtractorModel = None
                if extractor.venv:
                    # Run in special mode using the virtual environment detected
                    result = self.run_in_venv(sample_path, extractor)
                else:
                    result = decoder.run(open(sample_path, "rb"), matches=yara_matches)
                if result:
                    results[decoder.name].update(
                        {"config": result.dict(exclude_defaults=True, exclude_none=True)}
                    )
                elif yara_matches:
                    # YARA rules matched, but no configuration extracted
                    continue
                else:
                    # No result
                    results.pop(decoder.name, None)
            except Exception as e:
                # Add exception to results
                results[decoder.name]['exception'] = str(e)
                self.log.error(e)
        return results

    def run_in_venv(self, sample_path: str, extractor: Extractor) -> ExtractorModel:
        # Load results and apply them against the model
        return ExtractorModel(**super().run_in_venv(sample_path, extractor))
