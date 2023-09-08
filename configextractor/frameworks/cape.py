# CAPE framework
from collections import defaultdict
from inspect import signature

from maco.model import ExtractorModel

from configextractor.frameworks.base import Extractor, Framework


class CAPE(Framework):
    @staticmethod
    def get_classification(extractor: Extractor):
        if hasattr(extractor.module, "TLP"):
            return extractor.module.TLP
        return None

    def validate(self, module):
        return hasattr(module, "extract_config") and len(signature(module.extract_config).parameters) == 1

    def run(self, sample_path, parsers):
        results = defaultdict(dict)
        for parser, yara_matches in parsers.items():
            # Just run CAPE parsers as-is
            parser_name = CAPE.get_name(parser)
            try:
                results[parser_name].update(
                    {
                        "author": parser.module.AUTHOR if hasattr(parser.module, "AUTHOR") else "<MISSING_AUTHOR>",
                        "description": parser.module.DESCRIPTION
                        if hasattr(parser.module, "DESCRIPTION")
                        else "<MISSING_DESCRIPTION>",
                        "config": {},
                    }
                )
                if parser.venv:
                    raise NotImplementedError()
                else:
                    result = parser.module.extract_config(open(sample_path, "rb").read())
                if result:
                    results[parser_name].update(
                        {"config": ExtractorModel(**result).dict(exclude_defaults=True, exclude_none=True)}
                    )
                elif yara_matches:
                    # YARA rules matched, but no configuration extracted
                    continue
                else:
                    # No result
                    results.pop(parser_name, None)
            except Exception as e:
                results[parser_name]["exception"] = str(e)
                self.log.error(f"{parser_name}: {e}")

        return results
