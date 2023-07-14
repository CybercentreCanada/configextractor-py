# ConfigExtractor

Maintainer: @cccs-rs

Python Library for ConfigExtractor

The code found in this repository contains a command line interface that acts as
a wrapper for popular malware configuration data decoders from:

- MaCo: https://github.com/CybercentreCanada/Maco [MIT license]
- MWCP framework: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP [MIT license]
- RATDecoder: https://github.com/kevthehermit/RATDecoders [MIT license]
- CAPE Sandbox: https://github.com/kevoreilly/CAPEv2/ [GPL license] (many thanks to @kevoreilly for releasing so many open source parsers).
- MWCFG : https://github.com/c3rb3ru5d3d53c/mwcfg [BSD 3-Clause License]
- malduck 🦆: https://github.com/CERT-Polska/malduck [GPL license]

## Installation Guide

### Setup YARA on Host

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

### Running in a Container

```bash
docker container run -it \
  -v /path/to/parsers:/mnt/parsers \
  -v /path/to/samples:/mnt/samples \
  cccs/assemblyline-service-configextractor bash
```

## Usage

### Command-line

You can use `configextractor` or `cx` to make use of the CLI:

```
Usage: cx [OPTIONS] PARSERS_PATH SAMPLE_PATH

Options:
  --block_list TEXT  Comma-delimited list of parsers to ignore
  --help             Show this message and exit.
```

### Python

```python
from configextractor.main import ConfigExtractor
import logging

# Create a logger to track ongoings
logger = logging.getLogger()
logger.handlers = [logging.StreamHandler()]
logger.setLevel('DEBUG')

# Instantiate instance of class with path(s) to extractors
# Attaching a logger will allow some insight into what's going on if parser detection is the issue
cx = ConfigExtractor(["/path/to/extractors/"], logger=logger)

# List all parsers actively detected and loaded into instance
# cx.parsers.keys() lists all the filesystem paths to the parsers
print([cx.get_details(p)['name'] for p in cx.parsers.keys()])

# Run all loaded parsers against sample
results = cx.run_parsers('/path/to/sample')

# Output raw results to stdout, each should be organized by the parsers that generated an output
print(results)
```

## Adding a new Parser Framework

1. Inherit from the base `Framework` class and implement class accordingly
2. Add new framework to the ConfigExtractor class' `FRAMEWORK_LIBRARY_MAPPING`
