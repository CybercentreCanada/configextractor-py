import json
import os
import subprocess
from logging import Logger
from tempfile import NamedTemporaryFile
from typing import Any, Dict, List

import plyara
import yara
from plyara.utils import rebuild_yara_rule


class Extractor:
    def __init__(self, framework, module, module_path, root_directory, yara_rule, venv=None) -> None:
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

    # Extract YARA rules from module
    def extract_yara_from_module(self, decoder: object, module_name: str, existing_rule_names=[]) -> List[str]:
        if self.yara_attr_name and hasattr(decoder, self.yara_attr_name) and getattr(decoder, self.yara_attr_name):
            yara_rules = list()
            # Modify YARA rule to include meta about the parser
            yara_parser = plyara.Plyara()
            for yara_rule_frag in yara_parser.parse_string(getattr(decoder, self.yara_attr_name)):
                # If this rule came with no metadata then instantiate it
                if not yara_rule_frag.get("metadata"):
                    yara_rule_frag["metadata"] = list()
                yara_rule_name = yara_rule_frag["rule_name"]
                yara_rule_frag["metadata"].extend(
                    [
                        {"yara_identifier": yara_rule_name},
                        {"parser_module": module_name},
                    ]
                )

                # Modify the name of the rule to avoid duplicate identifiers during compilation
                if yara_rule_name in existing_rule_names:
                    yara_rule_frag[
                        "rule_name"
                    ] = f"{yara_rule_name}_{len([i for i in existing_rule_names if i.startswith(yara_rule_name)])}"

                existing_rule_names.append(yara_rule_name)
                rebuilt_rule = rebuild_yara_rule(yara_rule_frag)
                try:
                    yara.compile(source=rebuilt_rule)
                    yara_rules.append(rebuilt_rule)
                except Exception as e:
                    self.log.error(f"{decoder.__name__}: {e}")
            return yara_rules

    # Validate module against framework
    def validate(self, module: Any) -> bool:
        NotImplementedError()

    # Run a series of modules
    def run(self, sample_path: str, parsers: Dict[Extractor, List[yara.Match]]) -> Dict[str, dict]:
        return NotImplementedError()

    def run_in_venv(self, sample_path: str, extractor: Extractor) -> Dict[str, dict]:
        # Write temporary script in the same directory as extractor to resolve relative imports
        python_exe = os.path.join(extractor.venv, "bin", "python")
        with NamedTemporaryFile("w", dir=os.path.dirname(extractor.module_path), suffix=".py") as script:
            with NamedTemporaryFile("w") as yara_rule:
                yara_rule.write(extractor.rule)
                yara_rule.flush()
                with NamedTemporaryFile() as output:
                    module_name = extractor.module.__module__.split(".")[-1]
                    module_class = extractor.module.__name__
                    script.write(
                        self.venv_script.format(
                            module_name=module_name,
                            module_class=module_class,
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
