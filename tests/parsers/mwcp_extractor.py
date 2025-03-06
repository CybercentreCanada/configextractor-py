"""Test MWCP extractor."""

from mwcp import Parser


# Format of MWCP parsers that are detected by library
class MWCP(Parser):
    """Represents a MWCP parser."""

    DESCRIPTION = "test"
