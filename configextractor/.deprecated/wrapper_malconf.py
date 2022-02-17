from collections import defaultdict
import os
import sys
import json
from malwareconfig import fileparser
from malwareconfig.modules import __decoders__, __preprocessors__
import logging

log_level = os.getenv('LOG_LEVEL') or 'INFO'
handler = logging.StreamHandler(sys.stdout)
logger = logging.getLogger('configextractor.wrapper_malconf')
logger.setLevel(log_level)
if sys.stdin.isatty():
    # if running as cli then redirect logs to stdout
    logger.addHandler(handler)


def preprocess(file_path):
    # Open and parse the file
    logger.info("[+] Loading File: {0}".format(file_path))
    file_info = fileparser.FileParser(file_path=file_path)
    logger.info("  [-] Found: {0}".format(file_info.malware_name))
    # First we preprocesss
    # Check for a packer we can unpack
    if file_info.malware_name in __preprocessors__:
        logger.info("  [+] Running PreProcessor {0}".format(file_info.malware_name))
        module = __preprocessors__[file_info.malware_name]['obj']()
        module.set_file(file_info)
        module.pre_process()

    return file_info


def process_file(file_info):
    if file_info.malware_name in __decoders__:
        logger.info("  [-] Running Decoder")
        module = __decoders__[file_info.malware_name]['obj']()
        module.set_file(file_info)
        module.get_config()
        conf = module.config
        logger.info("  [-] Config Output\n")
        if not conf:
            conf = defaultdict(lambda: '')
        for k, v in conf.items():
            if isinstance(v, bytes):
                try:
                    conf[k] = v.decode()
                except UnicodeDecodeError:
                    conf[k] = str(v)[2:-1]
        json_config = json.dumps(conf, indent=4, sort_keys=True)
        logger.info(json_config)
        return conf
    else:

        return "[!] No RATDecoder or File is Packed"


def list_decoders():
    logger.info("[+] Listing Decoders")
    for name in __decoders__.keys():
        logger.info("  [-] Loaded: {0}".format(name))

    logger.info("[+] Listing PreProcessors")
    for name in __preprocessors__.keys():
        logger.info("  [-] Loaded: {0}".format(name))
    sys.exit()


def check_file(f_path=None):
    # We need at least one arg
    if f_path == None:
        logger.info("[!] Not enough Arguments, Need at least file path\n")
        sys.exit()
    # Check for file or dir
    is_file = os.path.isfile(f_path)
    is_dir = os.path.isdir(f_path)
    if is_dir:
        logger.info("[!] Path is directory not a file.\n")
        sys.exit()
    if not is_file:
        logger.info("[!] You did not provide a valid file.\n")
        sys.exit()


if __name__ == "__main__":
    logger.info("[+] RATDecoders Running")
    path = sys.argv[1]
    check_file(path)
    file = preprocess(path)
    output = process_file(file)
