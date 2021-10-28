# ConfigExtractor
Python Library for ConfigExtractor

To ensure you get all the required modules OOB, be sure to perform a:

`git clone --recurse-submodules https://github.com/CybercentreCanada/configextractor-py`

The code found in this repository contains a command line interface that acts as
a wrapper for popular malware configuration data decoders from:
* MWCP framework: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP [MIT license]
* RATDecoder: https://github.com/kevthehermit/RATDecoders [MIT license]
* CAPE Sandbox: https://github.com/kevoreilly/CAPEv2/ [GPL license] (many thanks to @kevoreilly for releasing so many open source parsers).
* MWCFG : https://github.com/c3rb3ru5d3d53c/mwcfg [BSD 3-Clause License]

## Installation Guide
### Setup YARA
```bash
sudo apt-get update && sudo apt-get install -y git libssl-dev libmagic-dev automake libtool make gcc wget libjansson-dev pkg-config
export YARA_VERSION=4.1.0
wget -O /tmp/yara.tar.gz https://github.com/VirusTotal/yara/archive/v${YARA_VERSION}.tar.gz
tar -zxf /tmp/yara.tar.gz -C /tmp
cd /tmp/yara-${YARA_VERSION}
./bootstrap.sh
./configure --enable-magic --enable-dotnet --with-crypto --prefix /tmp/yara_install
make
make install
```

### Install (modified) RATDecoder from kevthehermit and ConfigExtractor CLI
From `configextractor-py`:
```bash
pip install RATDecoders/
pip install .
```

## Usage
The CLI has a parameter for providing the path to your dependencies directory. See `dependencies` folder as a starting point.

### Directory Structure of Dependencies
The dependency directory is expected to have the following format:
```text
arbitrary_dependency_foldername
.
├── mwcfg-modules (submodule from c3rb3ru5d3d53c)
│   ├── parser_config.yaml
│   ├── __init__.py
│   ├── example_parser.py
│   └── ...
├── mwcp_parsers
│   ├── parser_config.yaml
│   ├── __init__.py
│   ├── example_parser.py
│   └── ...
├── tag_rules
│   ├── example_tag_rule.rule
│   └── ...
├── yara_parser.yaml
├── yara_rules
│  ├── example_yara_rule.yara
|  └── ...
```

### Command-line Usage
You can use `configextractor` or `cx` to make use of the CLI:
```
configextractor <DEPENDENCY_PATH> <SAMPLE_PATH>
```



## Editing `yara_parser.yaml`
 The yara_parser.yaml file is used to run a parser under 3 different scenarios defined under 'selector'.
 * Yara rule match on file
 * Yara rule match on tag
 * Run all parsers

 If for either 'yara_rule' or 'tag' a match is found the parser(s) underneath are run.
 Tags come from a previous service(ConfigExtractor runs as a secondary service)
 If under the 'selector' section 'wildcard' is found, then all parsers defined in the 'parser' section are run.

 Adding an entry can be done by following the existing format. In each entry every field must be
 indented by 2 spaces. Under the 'parser' field different types of parsers will be supported
 (MWCP,CAPE), as of yet only MWCP parsers are supported.
 If 'yara_rule' exists under 'selector' then it must contain at least one or more directories.
 As well if 'tag' exists under 'selector' then it must contain one or more directories.
 If neither 'yara_rule' or 'tag' exist then the only way for parser to run is be added as a 'wildcard'
 parser which will run all parsers defined under it every time a file is submitted.

## Customization
When creating a new MWCP parser, follow the setup [here](https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/blob/master/docs/ParserDevelopment.md)

## Example entry in yara_parser.yaml
```text

Emotet:
  description: Emotet parser and yara rule for payload
  selector: # yara rules that match will run parser(s) defined under parser
    yara_rule:
      - ./yara_rules/emotet.yara # rule must be present in yara_rules directory
  parser:
      - MWCP:
        - Emotet # Emotet.py must be in mwcp_parsers directory, case matters

# Another example

Emotet:
  description: Emotet parser and yara rules for both payload and assemblyline tags
  classification: 'TLP:W' # output result classification; may be ommitted
  category: 'MALWARE'
  mitre_group: 'APTXX'  # actor/mitre_group from "https://attack.mitre.org/groups/"
  mitre_att: 'S0367'  # any valid MITRE ATT&CK ID codes
  malware: 'Emotet'  # the malware name that shows up in assemblyline implant tags
  malware_type: # any field from malware_types https://github.com/CybercentreCanada/CCCS-Yara/blob/master/CCCS_YARA_values.yml
    - 'Banker'
    - 'Loader'
  run_on: 'AND' # can be and/or, specifies whether either tag or file rule cause parsers to run or ifall rules have to match in order for parser to run
  selector: # at least one of the rules in yara_rule or tag must be positive for parser to run
    yara_rule: # both rules beneath will be run on file
      - ./yara_rules/emotet.yara # one or more rules may be added
      - ./yara_rules/emotet2.yara

    tag: # can be ommitted completely if yara_rule is present
      - ./tag_rules/emotet.rule # one or more rules may be added
      -./tag_rules/emotet2.rule
  parser:
      - MWCP:  # Multiple malware parsers will be run upon yara rule match
        - Emotet
        - QakBot
        - IcedID
```

## Adding a new Parser
1. Append entry to yara\_parser.yaml. Following format above. On startup an entry in parser\_config.yml should be created
2. Add yara rule defined in yara\_parser.yaml to yara\_rules directory.
3. Add tag rule defined in yara\_parser.yaml to tag\_rules directory (Optional)
4. Add parser to mwcp\_parsers directory


##### Note
Parser with wildcard in yara_parser.yml are default parsers that are run every time if no other matches are found. As well ensure classification is a valid field ("TLP:A","TLP:W").
