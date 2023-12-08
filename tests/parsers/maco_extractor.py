from maco.extractor import Extractor
from maco.model import ExtractorModel


class TestMACO(Extractor):
    author = "cccs-rs"
    family = "test"
    last_modified = "2023-12-07"

    def run(self, stream, matches):
        cfg = ExtractorModel(family="test")
        return cfg
