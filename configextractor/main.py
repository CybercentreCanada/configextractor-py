# Main module for ConfigExtractor library
import os
import yara

from collections import defaultdict
from configextractor.frameworks import CAPE, MALDUCK, MWCP, RATDECODER

FRAMEWORK_LIBRARY_MAPPING = {
    'CAPE': CAPE,
    # 'MALDUCK': MALDUCK,
    # 'MWCP': MWCP,
    # 'RATDECODER': RATDECODER,
}

class ConfigExtractor:
    def __init__(self, parsers_dir) -> None:
        parsers = [os.path.join(parsers_dir, file) for file in os.listdir(parsers_dir) if file.endswith('.py')]

        # Determine what kind of parser these are and extract the yara_rules
        self._yara_rules = list()
        validated_parsers = list()
        for fw_name, fw_class in FRAMEWORK_LIBRARY_MAPPING.items():
            fw_parsers = fw_class.validate_parsers(parsers)
            validated_parsers.extend(fw_parsers)
            self._yara_rules.extend(fw_class.extract_yara(fw_parsers))

        self.yara = yara.compile(source='\n'.join(self._yara_rules))
        self.parsers = validated_parsers


    def run_parsers(self, sample):
        results = dict()
        parsers_to_run = defaultdict(list)
        for yara_match in self.yara.match(sample):
            parser_path = yara_match.meta.get('parser_path')
            parser_framework = yara_match.meta.get('parser_framework')
            parsers_to_run[parser_framework].append(parser_path)

        for framework, parser_list in parsers_to_run.items():
            results[framework] = FRAMEWORK_LIBRARY_MAPPING[framework].run(sample, parser_list)

        return results
