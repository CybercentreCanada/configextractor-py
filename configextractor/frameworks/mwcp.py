# MWCP framework

import inspect
from logging import Logger
from typing import Dict, List

import mwcp
import regex
from maco.model import ConnUsageEnum, Encryption, ExtractorModel
from mwcp import Parser

from configextractor.frameworks.base import Extractor, Framework

IP_REGEX_ONLY = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"

CONN_USAGE = [k.name for k in ConnUsageEnum]
ENC_USAGE = [k.name for k in Encryption.UsageEnum]


def convert_to_MACO(metadata: list) -> dict:
    def handle_socket(meta: dict) -> dict:
        net_protocol = meta.get("network_protocol") or "tcp"
        host, port = meta["address"], None
        if ":" in host:
            host, port = meta["address"].split(":", 1)
        else:
            port = meta["port"]
        server_key = "server_ip" if regex.match(IP_REGEX_ONLY, host) else "server_domain"
        if net_protocol in ["tcp", "udp"]:
            conn = {server_key: host, "usage": "c2" if meta.get("c2") else conn_usage}
            if port:
                conn.update({"server_port": int(port)})
            net_list = config.setdefault(net_protocol, [])
            if conn not in net_list:
                net_list.append(conn)

    def handle_encryption(meta: dict) -> dict:
        # Encryption
        enc = {
            "algorithm": meta.get("algorithm"),
            "public_key": meta["key"],
            "mode": meta.get("mode"),
            "iv": meta.get("iv"),
            "usage": enc_usage,
        }
        enc_list = config.setdefault("encryption", [])
        if enc not in enc_list:
            enc_list.append(enc)

    config = {}
    for meta in metadata:
        # Determine the default connection if not a C2
        conn_usage = [t for t in meta["tags"] if t in CONN_USAGE] or ["other"]
        conn_usage = conn_usage[0]  # Use the first element to define connection usage

        enc_usage = [t for t in meta["tags"] if t in ENC_USAGE] or ["other"]
        enc_usage = enc_usage[0]  # Use the first element to define encryption usage

        if meta["type"] == "alphabet":
            # BaseXX alphabet
            True
        elif meta["type"] == "command":
            # Shell commands
            # TODO incorporate Shell commands into model
            True
        elif meta["type"] == "credential" and meta.get("password"):
            # Credentials
            config.setdefault("password", []).append(meta["password"])
        elif meta["type"] == "crypto_address":
            # Cryptocurrent Addresses
            config.setdefault("cryptocurrency", []).append({"address": meta["address"], "coin": meta.get("symbol")})
        elif meta["type"] == "decoded_string":
            # Decoded strings
            config.setdefault("decoded_strings", []).append(meta["value"])
            if meta["encryption_key"]:
                handle_encryption(meta["encryption_key"])
        elif meta["type"] == "email_address":
            # Email addresses
            # TODO incorporate found email addresses into model
            config.setdefault("other", {})["email_address"] = meta["value"]
        elif meta["type"] == "encryption_key":
            # Encryption
            handle_encryption(meta)
        elif meta["type"] == "event":
            # System Events
            # TODO incorporate System Events into model
            config.setdefault("other", {})["event"] = meta["value"]
        elif meta["type"] == "injection_process":
            # Victim Process
            if meta["value"] and meta["value"] not in ["None"]:
                config.setdefault("inject_exe", []).append(meta["value"])
        elif meta["type"] == "interval":
            # Interval associated to malware
            config.setdefault("sleep_delay", []).append(meta["value"])
        elif meta["type"] == "mission_id":
            # Campaign ID
            config.setdefault("campaign_id", []).append(meta["value"])
        elif meta["type"] == "mutex":
            # Mutex
            config.setdefault("mutex", []).append(meta["value"])
        elif meta["type"] == "path":
            # File path
            config.setdefault("paths", []).append({"path": meta["path"]})
        elif meta["type"] == "pipe":
            # Pipes
            config.setdefault("pipe", []).append(meta["value"])
        elif meta["type"] == "registry":
            # Registry
            config.setdefault("registry", []).append({"key": meta["value"]})
        elif meta["type"] == "service":
            # Windows service
            config.setdefault("service", []).append(
                {
                    "dll": meta.get("dll"),
                    "name": meta.get("name"),
                    "display_name": meta.get("display_name"),
                    "description": meta.get("description"),
                }
            )
        elif meta["type"] == "socket":
            # Socket
            handle_socket(meta)
        elif meta["type"] == "url":
            # Connections with
            if meta.get("url"):
                # RFC 3986 URL
                http = {
                    "uri": meta.get("url"),
                    "path": meta.get("path"),
                    "usage": "c2" if meta.get("socket", {}).get("c2", False) else conn_usage,
                }

                # Strip ending ':' in URIs
                if http["uri"] and http["uri"].endswith(":"):
                    http["uri"] = http["uri"][:-1]

                if meta.get("query"):
                    http.update({"query": meta["query"]})
                if meta.get("application_protocol"):
                    http.update({"protocol": meta["application_protocol"]})
                if meta.get("credential"):
                    http.update(
                        {
                            "username": meta["credential"].get("username"),
                            "password": meta["credential"].get("password"),
                        }
                    )
                config.setdefault("http", []).append(http)
            socket = meta.get("socket")
            if socket:
                if meta["application_protocol"] and meta["application_protocol"].lower() == "smtp":
                    # SMTP Connection
                    smtp = {"hostname": socket.get("address"), "usage": conn_usage}
                    if meta.get("credential"):
                        cred = meta["credential"]
                        smtp.update(
                            {
                                "username": cred.get("username"),
                                "password": cred.get("password"),
                            }
                        )
                    config.setdefault("smtp", []).append(smtp)
                else:
                    handle_socket(socket)
        elif meta["type"] == "user_agent":
            # User Agent
            config.setdefault("http", []).append({"user_agent": meta["value"]})
        elif meta["type"] == "uuid":
            # UUID
            config["identifier"] = meta["value"]
        elif meta["type"] == "version":
            # Version of malware
            config["version"] = meta["value"]
        elif meta["type"] == "other":
            if meta["key"].lower() == "family":
                config["family"] = meta["value"]
            elif "capability" in meta["tags"]:
                state = "enabled" if meta["value"] else "disabled"
                config.setdefault(f"capability_{state}", []).append(meta["key"].lower())
            else:
                # Catch-all
                config.setdefault("other", {})[meta["key"]] = meta["value"]
    return config


class MWCP(Framework):
    def __init__(self, logger: Logger, yara_attr_name=None):
        super().__init__(logger, yara_attr_name)
        self.venv_script = """
import importlib
import os
import sys
import json
import mwcp

parent_package_path = "{parent_package_path}"
sys.path.insert(1, parent_package_path)
mod = importlib.import_module("{module_name}")

result = mwcp.run(mod.{module_class}, data=open("{sample_path}", "rb").read())
with open("{output_path}", 'w') as fp:
    json.dump(result.as_json_dict(), fp)
"""

    def validate(self, parser):
        if inspect.isclass(parser):
            # 'DESCRIPTION' has to be implemented otherwise will raise an exception according to MWCP
            return issubclass(parser, Parser) and parser.DESCRIPTION

    def result_template(self, extractor: Extractor, yara_matches: List) -> Dict[str, str]:
        template = super().result_template(extractor, yara_matches)
        template.update(
            {
                "author": extractor.module.AUTHOR,
                "description": extractor.module.DESCRIPTION,
            }
        )
        return template

    def run(self, sample_path, parsers):
        results = list()

        for parser, yara_matches in parsers.items():
            parser_name = MWCP.get_name(parser)
            try:
                result = self.result_template(parser, yara_matches)

                r: dict = None
                if parser.venv:
                    r = self.run_in_venv(sample_path, parser)
                else:
                    # Just run MWCP parsers directly, using the filename to fetch the class attribute from module
                    r = mwcp.run(parser.module, data=open(sample_path, "rb").read()).as_json_dict()

                # Log any errors raised during execution
                [self.log.error(e) for e in r["errors"]]
                r = convert_to_MACO(r["metadata"])
                if not (r or yara_matches):
                    # Nothing of interest to report
                    continue

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
                result["exception"] = str(e)
                self.log.error(f"{parser.id}: {e}")
            results.append(result)
        return results
