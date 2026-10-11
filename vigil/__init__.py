"""vigil: a modular network intrusion detection engine.

Capture packets (live or from a pcap), normalize them into a single record
type, and run them through independent signature and behavioral detectors.
The package root stays import-light on purpose: heavy optional dependencies
(scapy for capture, click/rich for the CLI) are imported lazily where they are
used, so the detection core can be imported and tested with the standard
library alone.
"""

__version__ = "0.1.0"
