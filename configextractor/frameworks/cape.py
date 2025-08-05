"""CAPE Framework."""

import inspect
import re as regex
from logging import Logger
from multiprocessing import Manager, Process
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from maco import yara
from maco.model import ConnUsageEnum, Encryption, ExtractorModel

from configextractor.frameworks.base import Extractor, Framework

IP_REGEX_ONLY = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"

CONN_USAGE = [k.name for k in ConnUsageEnum]
ENC_USAGE = [k.name for k in Encryption.UsageEnum]

CAPE_YARA_RULE = """
rule CAPE {
    meta:
        desc = "Used to match on Python files that contain CAPE extractors"
    strings:
        $extractor_func = /def extract_config\(\w+(: bytes)?.*\)(-> \w+)?:/
    condition:
        $extractor_func
}
"""


def convert_to_MACO(cape_output: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Convert CAPE normalized output to MACO format.

    Reference: https://github.com/CAPESandbox/CAPE-parsers/blob/20681536887b8f92df00d6a4ec62b95e06a5d16f/README.md

    Args:
      cape_output (List[Dict[str, Any]]): Raw output from CAPE extractors

    Returns:
        (Dict[str, Any]): Data converted to MACO format

    """
    if not isinstance(cape_output, dict):
        return {"other": {"raw": cape_output}}

    # At a bare minimum, we'll preserve the original CAPE output before we begin parsing of normalized fields
    config = {}
    if "raw" not in cape_output:
        # We'll assume the output is in it's raw form
        config = {"other": {"raw": cape_output}}
    else:
        # We'll assume there's been some fields that have been normalized but also contains the raw output
        config = {"other": {"raw": cape_output["raw"]}}

    # CNCs
    CNCs = cape_output.get("CNCs", [])
    for c2_string in CNCs:
        # Parse the C2 url to determine the protocol
        parsed_url = urlparse(c2_string)
        scheme = parsed_url.scheme

        # Common connection information we can extract from the parsed URL
        conn_data = {
            component: getattr(parsed_url, component)
            for component in ["hostname", "port", "username", "password", "path"]
        }
        conn_data["usage"] = "c2"
        if scheme.startswith("http"):
            conn_data.update({"protocol": scheme, "uri": c2_string, "user_agent": config.get("user_agent")})
            config.setdefault("http", []).append(conn_data)
        elif scheme == "ftp":
            config.setdefault(scheme, []).append(conn_data)
        elif scheme in ["tcp", "udp"]:
            # Map the host and port data to being affialiated with server
            conn_data["server_port"] = conn_data.pop("port")
            host = conn_data.pop("hostname")
            if regex.match(IP_REGEX_ONLY, host):
                conn_data["server_ip"] = host
            else:
                conn_data["server_domain"] = host
            config.setdefault(scheme, []).append(conn_data)

    # Campaign
    campaign = cape_output.get("campaign")
    if campaign:
        config["campaign_id"] = [str(campaign)]

    # Botnet
    # TODO: Unsure if we have something to map Botnet information in MACO

    # DGA Seed
    # TODO: Unsure if we have something to map DGA seed information in MACO

    # Version
    version = cape_output.get("version")
    if version:
        config["version"] = version

    # Mutex
    mutex = cape_output.get("mutex")
    if mutex:
        config["mutex"] = [str(mutex)]

    # Build
    build = cape_output.get("build")
    if build:
        config["identifier"] = [str(build)]

    # Encryption
    encryption = {}
    if "cryptokey" in cape_output:
        encryption["key"] = cape_output["cryptokey"]

    if "cryptokey_type" in cape_output:
        encryption["algorithm"] = cape_output["cryptokey_type"]

    if encryption:
        config["encryption"] = [encryption]

    return config


class CAPE(Framework):
    """CAPE framework for configuration extraction."""

    def __init__(self, logger: Logger):
        """Initialize the CAPE framework.

        Args:
          logger (Logger): Logger to use
        """
        super().__init__(logger, "AUTHOR", "DESCRIPTION", None, "rule_source")
        self.venv_script = """
import importlib
import os
import sys
import json

parent_package_path = "{parent_package_path}"
sys.path.insert(1, parent_package_path)
mod = importlib.import_module("{module_name}.{module_class}")

result = mod.extract_config(open("{sample_path}", "rb").read())
if result:
    with open("{output_path}", 'w') as fp:
        json.dump(result, fp)
"""
        self.yara_rule = CAPE_YARA_RULE

    def validate(self, module: object) -> bool:
        """Validate the extractor module using attributes we expect to find in CAPE extractors.

        Args:
          module (object): Extractor module

        Returns:
            (bool): True if the module is valid, False otherwise

        """
        return hasattr(module, "extract_config") and inspect.isfunction(module.extract_config)

    def extract_yara(self, decoder) -> Optional[str]:
        """Extract YARA rules from CAPE parser module.

        Args:
          decoder (object): Module to extract YARA rule from

        Returns:
          (Optional[str]): YARA rule of the module if found, None otherwise
        """
        yara_rules = []
        # There a multiple variable names across the CAPE extractors (both community and core)
        # where we can extract YARA rules from that target the extractor
        for rule_var in ["yara_rule", "rule_source", "YARA_RULES", "RULE_SOURCE"]:
            if hasattr(decoder, rule_var):
                yara_rules.append(getattr(decoder, rule_var))

        if yara_rules:
            return "\n".join(yara_rules)

    def run(self, sample_path: str, parsers: Dict[Extractor, List[yara.Match]], timeout: int) -> List[dict]:
        """Run CAPE parsers on a sample.

        Args:
          sample_path (str): Path to the sample to run the modules on
          parsers (Dict[Extractor, List[yara.Match]]): Extractor modules and their YARA matches
          timeout (int): How long to wait for the extractor to finish

        Returns:
            (List[dict]): List of results from the modules

        """
        with Manager() as manager:
            results = manager.list()

            def run_extractor(parser: Extractor, yara_matches: List[str], results: List[Dict]) -> None:
                parser_name = CAPE.get_name(parser)
                try:
                    result = self.result_template(parser, yara_matches)

                    r: dict = None
                    if parser.venv:
                        r = self.run_in_venv(sample_path, parser)
                    else:
                        # Just run CAPE parsers directly by invoking `extract_config` directly
                        with open(sample_path, "rb") as f:
                            try:
                                r = parser.module.extract_config(f.read())
                            except Exception as e:
                                self.log.error(e)

                    if not isinstance(r, dict):
                        # Assume an exception was caught and returned as part of the output
                        raise Exception(r["raw"])
                    else:
                        # Check to see if extracted configuration contains nothing but null-ish values
                        if all([not v for v in r.values()]):
                            return

                    r = convert_to_MACO(r)
                    if not (r or yara_matches):
                        # Nothing of interest to report
                        return

                    family = parser_name
                    for y in yara_matches:
                        if y.meta.get("malware"):
                            family = y.meta["malware"]
                            break

                    r["family"] = family
                    result.update(
                        {
                            "config": ExtractorModel(**r).model_dump(exclude_defaults=True, exclude_none=True),
                        }
                    )

                except Exception as e:
                    exception = str(e)
                    if exception:
                        result["exception"] = str(e)
                        self.log.error(f"{parser.id}: {e}")
                    else:
                        # No meaningful exception raised
                        return
                results.append(result)

            processes = []
            for extractor, yara_matches in parsers.items():
                p = Process(
                    target=run_extractor,
                    args=(extractor, yara_matches, results),
                )
                p.start()
                processes.append(p)

            # Wait for all processes to finish
            for p in processes:
                p.join(timeout)

            return list(results)
