import json
import os
import subprocess
import sys
from logging import Logger
from tempfile import NamedTemporaryFile
from typing import Any, Dict, List

import plyara
import yara
from plyara.utils import rebuild_yara_rule


class Extractor:
    def __init__(self, id, framework, module, module_path, root_directory, yara_rule, venv=None) -> None:
        self.id = id
        self.framework = framework
        self.module = module
        self.module_path = module_path
        self.root_directory = root_directory
        self.rule = yara_rule
        self.venv = venv


class Framework:
    def __init__(self, logger: Logger, yara_attr_name=None):
        self.log = logger
        self.yara_attr_name = yara_attr_name
        self.venv_script = ""

    @staticmethod
    # Get classification of module
    def get_classification(extractor: Extractor) -> str:
        return None

    @staticmethod
    # Get name of module
    def get_name(extractor: Extractor):
        return extractor.module.__name__.split(".")[-1]

    # Define a template for results from this Extractor
    def result_template(self, extractor: Extractor, yara_matches: List[yara.Match]) -> Dict[str, str]:
        return dict(id=extractor.id, yara_hits=[y.rule for y in yara_matches])

    # Extract YARA rules from module
    def extract_yara_from_module(self, decoder: object) -> List[str]:
        if self.yara_attr_name and hasattr(decoder, self.yara_attr_name) and getattr(decoder, self.yara_attr_name):
            yara_parser = plyara.Plyara()
            return [
                rebuild_yara_rule(yara_rule_frag)
                for yara_rule_frag in yara_parser.parse_string(getattr(decoder, self.yara_attr_name))
            ]
        return []

    # Validate module against framework
    def validate(self, module: Any) -> bool:
        NotImplementedError()

    # Run a series of modules
    def run(self, sample_path: str, parsers: Dict[Extractor, List[yara.Match]]) -> List[dict]:
        return NotImplementedError()

    def run_in_venv(self, sample_path: str, extractor: Extractor) -> Dict[str, dict]:
        # Write temporary script in the same directory as extractor to resolve relative imports
        python_exe = os.path.join(extractor.venv, "bin", "python")
        with NamedTemporaryFile("w", dir=os.path.dirname(extractor.module_path), suffix=".py") as script:
            with NamedTemporaryFile("w") as yara_rule:
                yara_rule.write(extractor.rule)
                yara_rule.flush()
                with NamedTemporaryFile() as output:
                    module_name = extractor.module.__module__
                    module_class = extractor.module.__name__
                    module_package_path = None
                    for path in sys.path:
                        # Look for the package path that's relevant to the module path of the extractor
                        if extractor.module_path.startswith(path) and path.endswith(module_name.split(".", 1)[0]):
                            module_package_path = os.path.dirname(path)
                            break
                    script.write(
                        self.venv_script.format(
                            module_name=module_name,
                            module_class=module_class,
                            module_package_path=module_package_path,
                            sample_path=sample_path,
                            output_path=output.name,
                            yara_rule=yara_rule.name,
                        )
                    )
                    script.flush()
                    custom_module = (
                        script.name.split(".py")[0].replace(f"{extractor.root_directory}/", "").replace("/", ".")
                    )
                    proc = subprocess.run(
                        [python_exe, "-m", custom_module],
                        cwd=extractor.root_directory,
                        capture_output=True,
                    )
                    try:
                        # Load results and return them
                        output.seek(0)
                        return json.load(output)
                    except Exception:
                        # If there was an error raised during runtime, then propagate
                        delim = f'File "{extractor.module_path}"'
                        exception = proc.stderr.decode()
                        if delim in exception:
                            exception = f"{delim}{exception.split(delim, 1)[1]}"
                        raise Exception(exception)
