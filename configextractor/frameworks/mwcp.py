# MWCP framework

import inspect
import mwcp

from configextractor.frameworks.base import Framework
from mwcp import Parser


class MWCP(Framework):
    def validate(self, parser):
        if inspect.isclass(parser):
            return issubclass(parser, Parser) and (parser.AUTHOR or parser.DESCRIPTION)

    def run(self, sample_path, parsers):
        results = dict()

        for parser, yara_matches in parsers.items():
            parser_name = MWCP.get_name(parser)
            try:
                # Just run MWCP parsers directly, using the filename to fetch the class attribute from module
                result = mwcp.run(parser, data=open(sample_path, 'rb').read()).as_dict()
                if result:
                    [self.log.error(e) for e in result.get('errors', [])]
                    if result.get('metadata'):
                        return results.update({parser.__name__: result})
            except Exception as e:
                self.log.error(f"{parser_name}: {e}")
        return results
