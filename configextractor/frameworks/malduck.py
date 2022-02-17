# MALDUCK framework

import os
from typing import List, Dict
from importlib.machinery import SourceFileLoader
from configextractor.frameworks.base import Framework
from subprocess import run as run_subprocess
import json

from malduck import Extractor


class MALDUCK(Framework):
    @staticmethod
    def validate_parsers(parsers):

        # Helper function for MALDUCK validation
        def is_valid(parser_dir_path: str):
            parser_name = os.path.basename(parser_dir_path)

            for parser_path in os.listdir(parser_dir_path):
                if not parser_path.endswith('.py') or parser_name.startswith('test_') or parser_name == '__init__.py':
                    # If file is marked as a test file or isn't a python file, ignore
                    continue

                # All MALDUCK parsers import a common class
                parser_path = os.path.join(parser_dir_path, parser_path)
                try:
                    parser = SourceFileLoader(parser_name, parser_path).load_module()
                    if hasattr(parser, 'Extractor') and parser.Extractor == Extractor:
                        return True
                except Exception as e:
                    raise e

        new_parsers = []
        for path in parsers:
            if os.path.isdir(path):
                # Recurse through the directory and find the exact path to the parsers
                for root, subdirs, _ in os.walk(path):
                    for subdir in subdirs:
                        # Only attempt validation if the directory contain Python files
                        parser = os.path.join(root, subdir)
                        if any(file.endswith('.py') for file in os.listdir(parser)) and is_valid(parser):
                            # De-duplicate directories that contain multiple parsers
                            if not any(root.startswith(parser_dir) for parser_dir in new_parsers):
                                new_parsers.append(root)

        return new_parsers

    @staticmethod
    def run(sample_path: str, parsers: List[str]) -> Dict[str, dict]:
        results = dict
        for modules_path in parsers:
            # MWCFG tool supports passing a directory containing all modules used for analysis
            output = run_subprocess(['mwcfg', '--input', sample_path, '-m', modules_path],
                                    capture_output=True, env=os.environ).stdout.decode().replace("'", '"')
            mal_results = json.loads(output)

            for result in mal_results:
                for config in result.get('configs', []):
                    results.update(config)

        return results
