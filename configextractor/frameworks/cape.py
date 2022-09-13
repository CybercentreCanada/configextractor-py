# CAPE framework
import plyara
import yara

from configextractor.frameworks.base import Framework
from maco.model import ExtractorModel
from plyara.utils import rebuild_yara_rule


class CAPE(Framework):
    @staticmethod
    def get_classification(module):
        if hasattr(module, "TLP"):
            return module.TLP
        return None

    def validate(self, module):
        return hasattr(module, "extract_config")

    def run(self, sample_path, parsers):
        results = dict()
        for parser, yara_matches in parsers.items():
            # Just run CAPE parsers as-is
            parser_name = CAPE.get_name(parser)
            try:
                result = parser.extract_config(open(sample_path, "rb").read())
                if result:
                    results.update(
                        {
                            parser_name: {
                                "author": parser.AUTHOR,
                                "description": parser.DESCRIPTION,
                                "config": ExtractorModel(**result).dict(exclude_defaults=True, exclude_none=True),
                            }
                        }
                    )
            except Exception as e:
                self.log.error(f"{parser_name}: {e}")

        return results
