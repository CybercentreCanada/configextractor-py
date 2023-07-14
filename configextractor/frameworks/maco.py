# MACO Framework

import inspect
from typing import Any, Dict, List

import yara
from maco.extractor import Extractor

from configextractor.frameworks.base import Framework


class MACO(Framework):
    @staticmethod
    def get_classification(module):
        if hasattr(module, 'sharing'):
            return module.sharing

    def validate(self, module: Any) -> bool:
        if inspect.isclass(module):
            return issubclass(module, Extractor)

    def run(self, sample_path: str, parsers: Dict[Any, List[yara.Match]]) -> Dict[str, dict]:
        results = dict()
        for decoder_module, yara_matches in parsers.items():
            try:
                decoder = decoder_module()
                config = {}
                if hasattr(decoder, "family") and decoder.family:
                    config["family"] = decoder.family
                else:
                    config["family"] = decoder.__class__.__name__
                # Run MaCo parser with YARA matches
                results[decoder.name] = {
                    "author": decoder.author,
                    "description": decoder.__doc__,
                    "config": config,
                }
                result = decoder.run(open(sample_path, "rb"), matches=yara_matches)
                if result:
                    results[decoder.name].update({"config": result.dict(exclude_defaults=True, exclude_none=True)})
                elif yara_matches:
                    # YARA rules matched, but no configuration extracted
                    continue
                else:
                    # No result
                    results.pop(decoder.name, None)
            except Exception as e:
                # Add exception to results
                results[decoder.name]["exception"] = str(e)
                self.log.error(e)
        return results
