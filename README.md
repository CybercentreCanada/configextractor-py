# ConfigExtractor

<a href="https://pypi.org/project/configextractor-py/#history"><img src="https://img.shields.io/pypi/v/configextractor-py.svg" alt="Latest Stable Release"></a>

Maintainer: @cccs-rs

Python Library for performing configuration extraction across multiple extraction frameworks (ie. Maco, MWCP, etc.). This tool is actively used in the [Assemblyline](https://cybercentrecanada.github.io/assemblyline4_docs/) project as a [service](https://github.com/CybercentreCanada/assemblyline-service-configextractor).

The code found in this repository contains a command line interface that acts as
a wrapper for popular malware configuration data decoders from:

- [Maco](https://github.com/CybercentreCanada/Maco) [MIT license]
- [MWCP](https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP) [MIT license]
- [CAPE Sandbox](https://github.com/kevoreilly/CAPEv2/) via Maco wrappers [GPL license]
  - many thanks to [@kevoreilly](https://github.com/kevoreilly) for releasing so many open source parsers.
- ~~MWCFG : https://github.com/c3rb3ru5d3d53c/mwcfg [BSD 3-Clause License]~~
  - [Pending support from malduck with structured output](https://github.com/CERT-Polska/malduck/pull/101)

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
docker container run \
  -v /path/to/parsers:/mnt/parsers \
  -v /path/to/samples:/mnt/samples \
  cccs/assemblyline-service-configextractor \
  "cx -p /mnt/parsers -s /mnt/samples"
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
# cx.parsers.keys() lists all the relative module paths to the parsers
# The value of each key is an Extractor object containing details for running the extractor (ie. venv location, YARA rule, etc.)
print([cx.get_details(p)['name'] for p in cx.parsers.values()])

# Run all loaded parsers against sample
results = cx.run_parsers('/path/to/sample')

# Output raw results to stdout, each should be organized by the parsers that generated an output
print(results)
```

## Adding a new Parser Framework

1. Inherit from the base `Framework` class and implement class accordingly
2. Add new framework to the ConfigExtractor class' `FRAMEWORK_LIBRARY_MAPPING`
