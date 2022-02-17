
# CAPE parsers
# Traits:
# - All contain extract_config()
# - YARA rules can be embedded in the parser and stored as a variable
# Runtime: These parsers can be run on their own by calling extract_config(), one-by-one

# malduck parsers
# Traits:
# - Organized as classes that are derived from malduck's Extractor classes
# - YARA rules related to the parser is stored as a tuple and assumed to be in the same directory as parser
# Runtime: Use mwcfg library to handle malduck extractors

# mwcp parsers
# Traits:
# - Organized as classes that are derived from mwcp's Parser classes
# Runtime: use mwcp to register directory of MWCP parsers and run samples

# RATDecoder parsers
# Traits:
# - Organized as classes that are derived from malwareconfig's Decoder classes
# Runtime: use malconf CLI to run sample with list of RATDecoders

# CCCS parsers
# Traits:
# - Use YARA rules to determine whether or not a parser should be run; dictated by a config file
# - Format of parser follows mwcp framework
# - Configuration file also contains metadata related to the parser ie. classification
# Runtime: CCCS parsers should continue to operate in the same fashion as it does currently
