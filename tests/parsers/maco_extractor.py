"""Test MACO extractor."""

from maco.extractor import Extractor
from maco.model import ExtractorModel


class MACO(Extractor):
    """Represents a configuration extractor module for the MACO framework."""

    author = "cccs-rs"
    family = "test"
    last_modified = "2023-12-07"

    def run(self, stream, matches) -> ExtractorModel:
        """Run the extractor on the stream.

        Args:
          stream: Stream to run the extractor on
          matches: YARA matches

        Returns:
          (ExtractorModel): Extracted test configuration

        """
        cfg = ExtractorModel(family="test", decoded_strings=[stream.read()])
        return cfg
