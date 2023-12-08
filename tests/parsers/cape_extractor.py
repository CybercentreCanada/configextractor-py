# Format of CAPE parsers that are detected by library
def extract_config(data):
    ...


# Similar function signatures to CAPE's included in another class
# This shouldn't be detected under the CAPE framework
# (ie. if found under a MACO implementation, then the detected framework will be MACO)
class CAPEWrapper:
    def extract_config(self):
        ...
