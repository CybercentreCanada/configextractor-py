from typing import List, Dict


class Framework():
    @staticmethod
    def validate_parsers(parsers: List[str]) -> List[str]:
        return NotImplementedError()

    @staticmethod
    def run(sample_path: str, parsers: List[str]) -> Dict[str, dict]:
        return NotImplementedError()
