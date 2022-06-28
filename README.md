# ConfigExtractor
Maintainer: @cccs-rs

Python Library for ConfigExtractor

The code found in this repository contains a command line interface that acts as
a wrapper for popular malware configuration data decoders from:
* MaCo: https://github.com/CybercentreCanada/Maco [MIT license]
* MWCP framework: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP [MIT license]
* RATDecoder: https://github.com/kevthehermit/RATDecoders [MIT license]
* CAPE Sandbox: https://github.com/kevoreilly/CAPEv2/ [GPL license] (many thanks to @kevoreilly for releasing so many open source parsers).
* MWCFG : https://github.com/c3rb3ru5d3d53c/mwcfg [BSD 3-Clause License]

## Installation Guide
### Setup YARA
```bash
sudo apt-get update && sudo apt-get install -y git libssl-dev libmagic-dev automake libtool make gcc wget libjansson-dev pkg-config
export YARA_VERSION=4.1.3
wget -O /tmp/yara.tar.gz https://github.com/VirusTotal/yara/archive/v${YARA_VERSION}.tar.gz
tar -zxf /tmp/yara.tar.gz -C /tmp
cd /tmp/yara-${YARA_VERSION}
./bootstrap.sh
./configure --enable-magic --enable-dotnet --with-crypto --prefix /tmp/yara_install
make
make install
pip install  --global-option="build" --global-option="--enable-dotnet" --global-option="--enable-magic" yara-python==$YARA_VERSION
```

### Command-line Usage
You can use `configextractor` or `cx` to make use of the CLI:
```
Usage: cx [OPTIONS] PARSERS_PATH SAMPLE_PATH

Options:
  --block_list TEXT  Comma-delimited list of parsers to ignore
  --help             Show this message and exit.
```

## Adding a new Parser Framework
1. Inherit from the base `Framework` class and implement class accordingly
2. Add new framework to the ConfigExtractor class' `FRAMEWORK_LIBRARY_MAPPING`
