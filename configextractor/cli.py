import ast
import click
import json
import logging
import mwcp
import os
import pkgutil
import re
import subprocess
import yaml
import yara
from pathlib import Path
from typing import List, Dict
from mwcp import metadata
import configextractor.wrapper_malconf as malconf

# Important file and directory paths
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
MWCP_PARSERS_DIR_PATH = ""
MWCP_PARSER_CONFIG_PATH = ""
MWCP_PARSER_PATHS = []
YARA_PARSER_PATH = ""
YARA_PARSERS = {}


DIRECTORY_LIST = ['Install Dir', 'InstallDir', 'InstallPath', 'Install Folder',
                  'Install Folder1', 'Install Folder2', 'Install Folder3',
                  'Folder Name', 'FolderName', 'pluginfoldername', 'nombreCarpeta']
DOMAINS_LIST = ['Domain', 'Domains', 'dns', 'C2']
PORT_LIST = ['p1', 'p2', 'Port', 'Port1', 'Port2', "Client Control Port", "Client Control Transfer"]
FILENAME_LIST = ['InstallName', 'Install Name', 'Exe Name',
                 'Jar Name', 'JarName', 'StartUp Name', 'File Name',
                 'USB Name', 'Log File', 'Install File Name']
FILEPATH_CONCATENATE_PAIR_LIST = {'Install Path': 'Install Name',
                                  'Install Directory': 'Install File Name'}
FTP_FIELD_PAIRS = {'FTP Server': 'FTP Folder',
                   'FTPHost': 'FTPPort', 'FTPHOST': 'FTPPORT'}
INJECTIONPROCESS_LIST = ['Process Injection', 'Injection', 'Inject Exe']
INTERVAL_LIST = ['FTP Interval', 'Remote Delay', 'RetryInterval']
MISSIONID_LIST = ['Campaign ID', 'CampaignID', 'Campaign Name',
                  'Campaign', 'ID', 'prefijo']
MUTEX_LIST = ['Mutex', 'mutex', 'Mutex Main', 'Mutex 4', 'MUTEX',
              'Mutex Grabber', 'Mutex Per']
NONC2_URL_LIST = ['Screen Rec Link', 'WebPanel', 'Plugins']
REGISTRYPATH_LIST = ['Domain', 'Reg Key', 'StartupName', 'Active X Key', 'ActiveX Key',
                     'Active X Startup', 'Registry Key', 'Startup Key', 'REG Key HKLM',
                     'REG Key HKCU', 'HKLM Value', 'RegistryKey', 'HKCUKey', 'HKCU Key',
                     'Registry Value', 'keyClase', 'regname', 'registryname',
                     'Custom Reg Key', 'Custom Reg Name', 'Custom Reg Value', 'HKCU',
                     'HKLM', 'RegKey1', 'RegKey2', 'Custom Reg Key', 'Reg Value']
VERSION_LIST = ['Version', 'version']
""" The following list is used when only a password is available, that is a password without
    a corresponding username. See username below if you have a username/password pair.
"""
PASSWORD_ONLY_LIST = ['Password', 'password']

""" Note: The username/password list are zipped together in pairs from the following
    two lists. There is a password only list above.
"""
USERNAME_LIST = ['FTP UserName', 'FTPUserName', 'FTPUSER']
PASSWORD_LIST = ['FTP Password', 'FTPPassword', 'FTPPASS']

SUPER_LIST = USERNAME_LIST + PASSWORD_LIST + PASSWORD_ONLY_LIST + VERSION_LIST + REGISTRYPATH_LIST + NONC2_URL_LIST + \
    MUTEX_LIST + MISSIONID_LIST + INTERVAL_LIST + INJECTIONPROCESS_LIST + \
    FILENAME_LIST + DOMAINS_LIST + DIRECTORY_LIST
FLCP = [item for pairs in FILEPATH_CONCATENATE_PAIR_LIST.items() for item in pairs]
FTPP = [item for pairs in FTP_FIELD_PAIRS.items() for item in pairs]
SUPER_LIST.extend(FTPP + FLCP)

# This Report object will be used as a global variable for each file submission (or each time you register it)
report = None


class Parser:
    def __init__(self, name: str, parser_list: List[str], compiled_rules: List[yara.Rules], classification: str,
                 malware: str, malware_types: List[str], mitre_group: str, mitre_att: str, category: str, run_on: str):
        self.name = name
        self.parser_list = parser_list
        self.compiled_rules = compiled_rules
        self.match = False
        self.classification = classification
        self.malware = malware
        self.malware_types = malware_types
        self.mitre_group = mitre_group
        self.mitre_att = mitre_att
        self.category = category
        self.run_on = run_on

    def __eq__(self, other):
        # TODO: Find a way to compare equality between yara.Rules objects (compiled_rules)
        return self.name == other.name and self.parser_list == other.parser_list and \
            self.match == other.match and self.classification == other.classification and \
            self.malware == other.malware and self.malware_types == other.malware_types and \
            self.mitre_group == other.mitre_group and self.mitre_att == other.mitre_att and \
            self.category == other.category


class Entry:
    # Entry defined in yara_parser.yaml used internally
    def __init__(self, description: str, classification: str, category: str, mitre_group: str,
                 mitre_att: str, malware: str, run_on: str, yara_rules: List[str],
                 malware_types: List[str], parsers: List[dict], selector: dict,
                 tag_rules: List[str] = None):
        self.description = description
        self.classification = classification
        self.category = category
        self.mitre_group = mitre_group
        self.mitre_att = mitre_att
        self.malware = malware
        self.run_on = run_on
        self.yara_rules = yara_rules
        self.tag_rules = tag_rules
        self.malware_types = malware_types
        self.parsers = parsers
        self.selector = selector


# Loading up YARA Parsers
def load_parsers():
    YARA_PARSERS_LOAD = yaml.full_load(open(YARA_PARSER_PATH, 'r'))
    for entry_name, dict_values in YARA_PARSERS_LOAD.items():
        selector = dict_values['selector']
        YARA_PARSERS[entry_name] = Entry(description=dict_values['description'],
                                         classification=dict_values['classification'],
                                         category=dict_values['category'],
                                         mitre_group=dict_values['mitre_group'],
                                         mitre_att=dict_values['mitre_att'],
                                         malware=dict_values['malware'],
                                         run_on=dict_values['run_on'],
                                         yara_rules=selector.get('yara_rule'),
                                         malware_types=dict_values['malware_type'],
                                         parsers=dict_values['parser'],
                                         tag_rules=selector.get("tag"),
                                         selector=selector)


def init_root_dependencies():
    global MWCP_PARSERS_DIR_PATH, MWCP_PARSER_CONFIG_PATH, MWCP_PARSER_PATHS, YARA_PARSER_PATH
    MWCP_PARSERS_DIR_PATH = os.path.join(ROOT_DIR, "mwcp_parsers")
    MWCP_PARSER_CONFIG_PATH = os.path.join(MWCP_PARSERS_DIR_PATH, "parser_config.yml")
    MWCP_PARSER_PATHS = [p for p in Path(MWCP_PARSERS_DIR_PATH).glob("[!_]*.py")]
    YARA_PARSER_PATH = os.path.join(ROOT_DIR, "yara_parser.yaml")


def validate_parsers(parser_list: List[dict]):
    mwcp_key = "MWCP"
    parsers_set = set()
    for parser in parser_list:
        if mwcp_key in parser:
            parsers_set.update(parser[mwcp_key])
        else:
            raise NameError(f"Parser type is invalid or unsupported, only {mwcp_key} supported")
    return list(parsers_set)


def check_paths(paths: List[str]):
    if paths:
        for path in paths:
            if not path:
                raise Exception("Path cannot be empty")
            abs_file_path = os.path.join(ROOT_DIR, path)
            if not os.path.isfile(abs_file_path):
                raise Exception("Rule ", abs_file_path, "does not exist")
        return True
    else:
        return False  # no path defined in yaml


def initialize_parser_objs(tags: dict = None):
    parser_objs = {}
    for parser_name, yara_parser in YARA_PARSERS.items():
        # if tags are present then get tag rule paths
        if tags:
            rule_source_paths = yara_parser.tag_rules
        else:
            rule_source_paths = yara_parser.yara_rules
        if not check_paths(rule_source_paths):
            continue
        validated_parsers = validate_parsers(yara_parser.parsers)
        compiled_rules = []
        for rule_source_path in rule_source_paths:
            abs_path = os.path.join(ROOT_DIR, rule_source_path)
            if tags:
                rule = yara.compile(filepath=abs_path, externals=tags)
            else:
                rule = yara.compile(filepath=abs_path)
            compiled_rules.append(rule)
        parser_objs[parser_name] = Parser(
            name=parser_name,
            parser_list=validated_parsers,
            compiled_rules=compiled_rules,
            classification=yara_parser.classification,
            malware=yara_parser.malware,
            malware_types=yara_parser.malware_types,
            mitre_group=yara_parser.mitre_group,
            mitre_att=yara_parser.mitre_att,
            category=yara_parser.category,
            run_on=yara_parser.run_on
        )
    return parser_objs


def validate_parser_config():

    pattern = '.*class.*(Parser).*'
    yaml_parsers = {}
    # find name of parser class
    for parser in MWCP_PARSER_PATHS:
        file = open(parser, "r")
        for line in file:
            if re.match(pattern, line):
                parser_class = line.partition("class ")[2].partition("(Parser):")[0]
                entry = {
                    "description": f"{parser.stem} Parser",
                    "author": "Not Found",
                    "parsers": [f".{parser_class}"]
                }
                yaml_parsers[parser.stem] = entry
        file.close()
    parsers_in_config = []
    # check that all parsers in dir are present in mwcp config
    with open(MWCP_PARSER_CONFIG_PATH, "w+", encoding='utf-8') as f:
        for entry, value in yaml_parsers.items():
            parsers_in_config.append(entry)
            p = {entry: value}
            yaml.dump(p, f)

    if len(MWCP_PARSER_PATHS) != len(parsers_in_config):
        raise Exception("Number of parsers in mwcp_parsers and parser_config.yml don't match: "
                        f"{len(MWCP_PARSER_PATHS)} != {len(parsers_in_config)}")


def run(parser_list: List[str], f_path: str):
    # all parsers in this list already matched
    # all parsers to be run must be in yml file in parser_dir
    outputs = {}
    reports = []
    for parser in parser_list:
        report = mwcp.run(parser, file_path=f_path)
        if report.metadata:
            outputs[parser] = report.metadata
            reports.append(report)
    if __name__ == '__main__' and parser_list:
        with open("output.json", "w") as fp:
            fp.write(str(json.dumps(outputs)))
    return outputs, reports


def check_names(parsers: set):
    mwcp_parsers = set()
    for file in MWCP_PARSER_PATHS:
        mwcp_parsers.add(file.stem)
    diff = parsers - mwcp_parsers
    if diff:
        raise Exception(f"{diff} not found in {MWCP_PARSER_PATHS}")


def deduplicate(file_pars, tag_pars, file_path, tags_dict=None) -> List[str]:
    # for each entry we get all compiled file yara rules and see if theres a match,
    # if there is a match then we add all parsers for that parser object to the super list
    def is_match(file_path: str, parser_objects: Dict, tags_dict=None) -> Dict[str, List[yara.Rules]]:
        nonlocal super_parser_list
        if parser_objects is not None:
            for pars, obj in parser_objects.items():
                matched_rules = []
                for rule in obj.compiled_rules:
                    # each compiled rule object from yara_rule in yml
                    matched_rule = rule.match(file_path, externals=tags_dict)
                    if matched_rule:
                        matched_rules.extend(matched_rule)
                        super_parser_list.extend(obj.parser_list)

    # eliminate common parsers between yara tag match and yara file match so parsers aren't run twice
    super_parser_list = []
    and_malware = {}  # dict containing parsers to be run that are specified as AND (both file and tag rules need match)
    # add wildcard parsers that are run under all conditions
    for parser_name in YARA_PARSERS:
        yara_parser = YARA_PARSERS[parser_name]
        if 'wildcard' in yara_parser.selector:
            wildcard_parsers = validate_parsers(yara_parser.parsers)
            super_parser_list.extend(wildcard_parsers)
        if 'AND' in yara_parser.run_on:  # everything else is OR by default
            if 'tag' in yara_parser.selector and 'yara_rule' in yara_parser.selector:
                # then match must exist for some parser for both tag and file
                malware_name = yara_parser.malware
                and_malware[malware_name] = parser_name
            else:
                raise Exception("AND cannot be specified without both tag and file yara rules")

    is_match(file_path, file_pars)
    is_match(file_path, tag_pars, tags_dict)

    # run check to exclude and parsers

    def all_rules_match(compiled_rules):
        ctr = 0
        for rule in compiled_rules:
            match = rule.match(file_path, externals=tags_dict)
            if match:
                ctr = ctr + 1
        if len(compiled_rules) == ctr:
            return True
        else:
            return False

    # Provide AND/OR run functionality
    for malware, top_name in and_malware.items():
        file_yara_rules = file_pars[top_name].compiled_rules
        tag_yara_rules = tag_pars[top_name].compiled_rules
        file_bool = all_rules_match(file_yara_rules)
        tag_bool = all_rules_match(tag_yara_rules)
        if file_bool and tag_bool:
            print("both file and tag rules have match")
        else:
            print('tag or file rule did not match, excluding...')
            malware_to_parsers = file_pars[top_name].parser_list
            super_parser_list = [x for x in super_parser_list if x not in malware_to_parsers]

    super_parser_list = [i[0].upper() + i[1:] for i in super_parser_list]
    super_parser_list_set = set(super_parser_list)
    check_names(super_parser_list_set)
    super_parser_set_list = list(super_parser_list_set)
    return super_parser_set_list


def compile(tags=None):
    # returns dict of parser names with Parser objects containing  compiled rules
    if tags is not None:
        parser_objs_tags = initialize_parser_objs(tags)
        parser_objs = initialize_parser_objs()
        return parser_objs, parser_objs_tags
    parser_objs = initialize_parser_objs()
    return parser_objs, None


def register(output_dir: str = None):
    global report
    if not output_dir:
        output_dir = os.getcwd()
    mwcp.register_entry_points()
    mwcp.register_parser_directory(MWCP_PARSERS_DIR_PATH)
    report = mwcp.Report(output_directory=output_dir)
    return report


def check_for_backslashes(ta_key, mwcp_key, data, report):
    IGNORE_FIELD_LIST = ['localhost', 'localhost*']
    if '\\' in data[ta_key]:
        report.add_metadata(mwcp_key, data[ta_key])
    elif '.' not in data[ta_key] and data[ta_key] not in IGNORE_FIELD_LIST:
        report.add_metadata(mwcp_key, data[ta_key])


def ta_mapping(output, scriptname=""):
    # takes malwareconfig json output matches to mwcp fields found in report.metadata
    c2_domains = {val: output[val] for val in DOMAINS_LIST if val in output}
    if c2_domains:
        c2_ports = {val: output[val] for val in PORT_LIST if val in output}
        map_c2_domains({**c2_domains, **c2_ports})
    mutexes = {val: output[val] for val in MUTEX_LIST if val in output}
    if mutexes:
        map_mutex(mutexes)
    registries = {val: output[val] for val in REGISTRYPATH_LIST if val in output}
    if registries:
        map_registry(registries)

    map_domainX_fields(output)
    map_ftp_fields(output)
    map_filepath_fields(scriptname, output)
    map_username_password_fields(output)

    mwcp_key_map = {
        'version': VERSION_LIST,
        'missionid': MISSIONID_LIST,
        'url': NONC2_URL_LIST,
        'injectionprocess': INJECTIONPROCESS_LIST,
        'interval': INTERVAL_LIST,
        'filename': FILENAME_LIST,
        'directory': DIRECTORY_LIST,
        'key': ['EncryptionKey']
    }

    for key, value in mwcp_key_map.items():
        refined = refine_data(output, value)
        if refined:
            map_fields(refined, key)

    if scriptname == 'unrecom':
        map_jar_fields(output)


def refine_data(output, keys_of_interest):
    return {val: output[val] for val in keys_of_interest if val in output}


def map_fields(data, mwcp_key):
    global report
    if not mwcp_key:
        return
    for key, val in data.items():
        report.add_metadata(mwcp_key, val)


def map_username_password_fields(data):
    global report
    for username, password in zip(USERNAME_LIST, PASSWORD_LIST):
        if username in data and password in data:
            report.add(metadata.Credential([data[username], data[password]]))
        elif password in data:
            report.add(metadata.Password(data[password]))
        elif username in data:
            report.add(metadata.Username(data[username]))

    passwords = {val: data[val] for val in PASSWORD_ONLY_LIST if val in data}
    map_fields(passwords, 'password')


def map_filepath_fields(scriptname, data):
    global report
    IGNORE_SCRIPT_LIST = ['Pandora', 'Punisher']
    for pname, fname in FILEPATH_CONCATENATE_PAIR_LIST.items():
        if scriptname not in IGNORE_SCRIPT_LIST:
            if pname in data:
                if fname in data:
                    report.add(metadata.FilePath(data[pname].rstrip("\\") + "\\" + data[fname]))
                else:
                    report.add(metadata.Directory(data[pname]))
            elif fname in data:
                report.add(metadata.FileName(data[fname]))
        else:
            if pname in data:
                report.add(metadata.Directory(data[pname]))
            if fname in data:
                report.add(metadata.FileName(data[fname]))


def map_ftp_fields(data):
    global report
    SPECIAL_HANDLING_PAIRS = {'FTP Address': 'FTP Port'}
    for host, port in SPECIAL_HANDLING_PAIRS.items():
        ftpdirectory = ''
        if 'FTP Directory' in data:
            ftpdirectory = data['FTP Directory']
        mwcpkey = ''
        if host in data:
            ftpinfo = "ftp://" + data[host]
            mwcpkey = 'c2_url'
        if port in data:
            if mwcpkey:
                ftpinfo += ':' + data[port]
            else:
                ftpinfo = [data[port], 'tcp']
                mwcpkey = 'port'
        if ftpdirectory:
            if mwcpkey == 'c2_url':
                ftpinfo += '/' + ftpdirectory
                report.add(metadata.C2URL(ftpinfo))
            elif mwcpkey:
                report.add(metadata.Directory(ftpdirectory))
            else:
                report.add(metadata.Directory(ftpdirectory))
        elif mwcpkey:
            report.add_metadata(mwcpkey, ftpinfo)

    for address, port in FTP_FIELD_PAIRS.items():
        if address in data:
            if port in data:
                report.add(metadata.C2URL("ftp://" + data[address] + "/" + data[port]))
            else:
                report.add(metadata.C2URL("ftp://" + data[address]))


def map_c2_domains(data):
    global report
    for domain_key in DOMAINS_LIST:
        if domain_key in data:
            """ Hack here to handle a LuxNet case where a registry path is stored
                under the Domain key. """
            if data[domain_key].count('\\') < 2:
                if '|' in data[domain_key]:
                    """ The '|' is a separator character so strip it if
                        it is the last character so the split does not produce
                        an empty string i.e. '' """
                    domain_list = data[domain_key].rstrip('|').split('|')
                elif '*' in data[domain_key]:
                    """ The '*' is a separator character so strip it if
                        it is the last character """
                    domain_list = data[domain_key].rstrip('*').split('*')
                else:
                    domain_list = [data[domain_key]]
                for addport in domain_list:
                    if ":" in addport:
                        report.add(metadata.Address(f"{addport}"))
                    elif 'p1' in data or 'p2' in data:
                        if 'p1' in data:
                            report.add(metadata.Address(f"{data[domain_key]}:{data['p1']}"))
                        if 'p2' in data:
                            report.add(metadata.Address(f"{data[domain_key]}:{data['p2']}"))
                    elif 'Port' in data or 'Port1' in data or 'Port2' in data:
                        if 'Port' in data:
                            # CyberGate has a separator character in the field
                            # remove it here
                            data['Port'] = data['Port'].rstrip('|').strip('|')
                            for port in data['Port']:
                                report.add(metadata.Address(f"{addport}:{data['Port']}"))
                        if 'Port1' in data:
                            report.add(metadata.Address(f"{addport}:{data['Port1']}"))
                        if 'Port2' in data:
                            report.add(metadata.Address(f"{addport}:{data['Port2']}"))
                    elif domain_key == 'Domain' and ("Client Control Port" in data or "Client Transfer Port" in data):
                        if "Client Control Port" in data:
                            report.add(metadata.Address(f"{data['Domain']}:{data['Client Control Port']}"))
                        if "Client Transfer Port" in data:
                            report.add(metadata.Address(f"{data['Domain']}:{data['Client Transfer Port']}"))
                    # Handle Mirai Case
                    elif domain_key == 'C2' and isinstance(data[domain_key], list):
                        for domain in data[domain_key]:
                            report.add(metadata.Address(domain))
                    else:
                        report.add(metadata.Address(addport))


def map_domainX_fields(data):
    global report
    SPECIAL_HANDLING_LIST = ['Domain1', 'Domain2']
    for suffix in range(1, 21):
        suffix = str(suffix)
        field = 'Domain' + suffix
        if field in data:
            if data[field] != ':0':
                if ':' in data[field]:
                    address, port = data[field].split(':')
                    report.add(metadata.Address(f"{address}:{port}"))
                else:
                    if field in SPECIAL_HANDLING_LIST:
                        if "Port" in data:
                            report.add(metadata.Address(f"{data[field]}:{data['Port']}"))
                        elif "Port" + suffix in data:
                            # customization if this doesn't hold
                            report.add(metadata.Address(f"{data[field]}:{data['Port' + suffix]}"))
                        else:
                            report.add(metadata.Address(data[field]))
                    else:
                        report.add(metadata.Address(data[field]))


def map_mutex(data):
    global report
    SPECIAL_HANDLING = 'Mutex'
    for key in data:
        val = data[key]
        if key == SPECIAL_HANDLING and val in ['false', 'true']:
            continue
        report.add(metadata.Mutex(val))


def map_registry(data):
    global report
    SPECIAL_HANDLING = 'Domain'
    for key in data:
        val = data[key]
        if key == SPECIAL_HANDLING:
            check_for_backslashes(key, 'registrypath', data, report)
        else:
            report.add(metadata.Registry(val))


def map_jar_fields(data):
    global report
    """This routine is for the unrecom family"""
    jarinfo = ''
    mwcpkey = ''
    if 'jarfoldername' in data:
        jarinfo = data['jarfoldername']
        mwcpkey = 'directory'
    if 'jarname' in data:
        # if a directory is added put in the \\
        if jarinfo:
            jarinfo += '\\' + data['jarname']
            mwcpkey = 'filepath'
        else:
            mwcpkey = 'filename'
            jarinfo = data['jarname']
        if 'extensionname' in data:
            jarinfo += '.' + data['extensionname']
    report.add_metadata(mwcpkey, jarinfo)


def run_ratdecoders(file_path, passed_report):
    global report
    report = passed_report
    file_info = malconf.preprocess(file_path)
    script_name = file_info.malware_name
    output = malconf.process_file(file_info)
    if type(output) is str:
        return output
    ta_mapping(output, script_name)

    for key in output:
        if key not in SUPER_LIST:
            report.add(metadata.Other(key, output[key]))
    return {script_name: report.metadata}  # TODO change report.metadata deprecated


def run_mwcfg(file_path, report):
    repo_path = os.path.dirname(os.path.abspath(__file__))
    extracted = []
    for path in ['mwcfg-modules', 'mwcfg-modules-custom']:
        output = []
        # check if directory actually contains parsers
        mod_path = os.path.join(repo_path, path)
        modules = [name for _, name, _ in pkgutil.iter_modules([mod_path])]
        if modules:
            process = subprocess.run(['mwcfg', '--input', f'{file_path}', '-m', mod_path], capture_output=True)
            output = ast.literal_eval(process.stdout.decode())
            if output[0]['configs']:
                extracted.append(output[0]['configs'])

    if extracted:
        for k, v in extracted[0].items():
            if k == 'urls':
                for url in v:
                    report.add(metadata.URL(url))
                continue
            try:
                report.add_metadata(k, v)
            except KeyError:
                report.add_metadata("other", {k: v})


def parse_file(file_path, report):
    run_ratdecoders(file_path, report)
    run_mwcfg(file_path, report)
    validate_parser_config()
    file_pars, tag_pars = compile()
    parsers = deduplicate(file_pars, tag_pars, file_path)
    outputs, reports = run(parsers, file_path)
    # for each parser entry check if match exists, if so run all parsers in parser_list for that entry
    # but can't run parsers until final list of parsers to run, from tag and file parsers is finished
    for report in reports:
        print(report.as_text())


@click.option("-d", "--debug", is_flag=True, help="Enables DEBUG level logs.")
@click.option("-v", "--verbose", is_flag=True, help="Enables INFO level logs.")
@click.command()
@click.argument('root_dir', type=click.Path(exists=True))
@click.argument('path', type=click.Path(exists=True))
def main(path, root_dir, debug, verbose) -> None:
    """
    Runs Malware parsers based on
    output of yara rules defined at and tags from AV hits
    Required args
    path : relative or absolute path to be analyzed
    """
    # if running cli mode tags are not expected
    if debug:
        logging.root.setLevel(logging.DEBUG)
    elif verbose:
        logging.root.setLevel(logging.INFO)

    global report, ROOT_DIR
    ROOT_DIR = root_dir
    init_root_dependencies()
    load_parsers()
    report = register()

    # Check if path given is a directory or a file
    if os.path.isfile(path):
        parse_file(path, report)
    else:
        # Iterate over directory
        for root, _, files in os.walk(path):
            for file in files:
                parse_file(os.path.join(root, file), report)


if __name__ == "__main__":
    main()
