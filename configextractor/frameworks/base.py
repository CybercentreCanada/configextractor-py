import os
from logging import Logger
from typing import List, Dict, Tuple


class Framework():
    def __init__(self, logger: Logger):
        self.log = logger

    @staticmethod
    def get_classification(parser_path) -> str:
        return None

    @staticmethod
    def get_name(parser_path) -> str:
        return os.path.basename(parser_path)[:-3]

    def extract_yara(self, parsers: List[str]) -> Tuple[List[str], List[str]]:
        return [], parsers

    def validate_parsers(self, parsers: List[str]) -> List[str]:
        return NotImplementedError()

    def run(self, sample_path: str, parsers: Dict[str, List[str]]) -> Dict[str, dict]:
        return NotImplementedError()
