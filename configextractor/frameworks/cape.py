# CAPE framework
from configextractor.frameworks.base import Framework
from maco.model import ExtractorModel


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
                results[parser_name] = {
                    "author": parser.AUTHOR,
                    "description": parser.DESCRIPTION,
                    "config": {},
                }
                result = parser.extract_config(open(sample_path, "rb").read())
                if result:
                    results[parser_name].update({
                        "config": ExtractorModel(**result).dict(exclude_defaults=True, exclude_none=True)
                    })
                elif yara_matches:
                    # YARA rules matched, but no configuration extracted
                    continue
                else:
                    # No result
                    results.pop(parser_name, None)
            except Exception as e:
                results[parser_name]['exception'] = str(e)
                self.log.error(f"{parser_name}: {e}")

        return results
