# CAPE framework
from inspect import signature
from typing import Any, Dict, List

import yara
from maco.model import ExtractorModel

from configextractor.frameworks.base import Extractor, Framework


class CAPE(Framework):
    @staticmethod
    def get_classification(extractor: Extractor):
        if hasattr(extractor.module, "TLP"):
            return extractor.module.TLP
        return None

    def validate(self, module: Any) -> bool:
        if hasattr(module, "extract_config"):
            s = signature(module.extract_config)
            # Ensure function isn't part of a class, which doesn't follow CAPE's extractor format
            return len(s.parameters) == 1 and "self" not in s.parameters

    def result_template(self, extractor: Extractor, yara_matches: List[yara.Match]) -> Dict[str, str]:
        template = super().result_template(extractor, yara_matches)
        template.update(
            {
                "author": extractor.module.AUTHOR if hasattr(extractor.module, "AUTHOR") else "<MISSING_AUTHOR>",
                "description": extractor.module.DESCRIPTION
                if hasattr(extractor.module, "DESCRIPTION")
                else "<MISSING_DESCRIPTION>",
            }
        )

        return template

    def run(self, sample_path: str, parsers: Dict[Extractor, List[yara.Match]]) -> List[dict]:
        results = list()
        for parser, yara_matches in parsers.items():
            # Just run CAPE parsers as-is
            parser_path = parser.module_path
            try:
                result = self.result_template(parser, yara_matches)
                if parser.venv:
                    raise NotImplementedError()
                else:
                    cfg = parser.module.extract_config(open(sample_path, "rb").read())

                if not (cfg or yara_matches):
                    # Nothing of interest to report
                    continue

                if cfg:
                    result.update({"config": ExtractorModel(**cfg).dict(exclude_defaults=True, exclude_none=True)})
            except Exception as e:
                # If an exception was raised at runtime, append to results
                result["exception"] = str(e)
                self.log.error(f"{parser_path}: {e}")

            results.append(result)

        return results
