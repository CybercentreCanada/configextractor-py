import inspect
import plyara
import yara


from configextractor.frameworks.base import Framework
from maco.extractor import Extractor
from plyara.utils import rebuild_yara_rule
from typing import Any, List, Dict


class MACO(Framework):
    @staticmethod
    def get_classification(module):
        # No standard for classification in MaCo format
        return None

    def validate(self, module: Any) -> bool:
        if inspect.isclass(module):
            return issubclass(module, Extractor)

    def run(self, sample_path: str, parsers: Dict[str, List[str]]) -> Dict[str, dict]:
        results = dict()
        for decoder_module, yara_matches in parsers.items():
            try:
                decoder = decoder_module()
                # Run MaCo parser with YARA matches
                results[decoder.name] = {
                    "author": decoder.author,
                    "description": decoder.__doc__,
                    "config": {},
                }
                result = decoder.run(open(sample_path, "rb"), matches=yara_matches)
                if result:
                    results[decoder.name].update(
                        {"config": result.dict(exclude_defaults=True, exclude_none=True)}
                    )
            except Exception as e:
                self.log.error(e)
            finally:
                break
        return results
