"""End-to-end test: read a real pcap off disk and run the full pipeline.

The unit tests feed hand-built packets; this one proves the capture layer and
the engine agree on a genuine capture file. It is skipped when scapy is not
installed so the scapy-free core can still be tested anywhere.
"""

import importlib.util
import os

import pytest

pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("scapy") is None, reason="scapy not installed"
)

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sample.pcap")


def test_replays_sample_pcap_and_finds_every_attack():
    from vigil.capture.pcap import PcapSource
    from vigil.pipeline import Pipeline

    pipe = Pipeline()
    pipe.run(PcapSource(FIXTURE))

    categories = {a.category for a in pipe.alerts}
    assert {"Port Scan", "SYN Flood", "Brute Force", "SQL Injection"} <= categories
    assert pipe.flows.total_packets == 406
