# Design notes

This document records why vigil is built the way it is, where it breaks, and
what would change at scale. It is meant to be read next to the code.

## Goals and non-goals

The goal is a detection engine that is correct, readable and fast enough to
matter, with a clean seam between capturing traffic and reasoning about it. It
is explicitly not a Snort or Suricata replacement: there is no TCP reassembly,
no protocol state machine, no rule-language parser. Those are deep projects of
their own. vigil aims to be a well-engineered core that does a focused job and
is honest about its edges.

## One record type

Everything downstream of capture sees a single `Packet` dataclass (`models.py`)
and nothing else. A capture source, whether live or a pcap, is the only code
that touches scapy; it flattens each frame into fields the detectors actually
use (addresses, ports, TCP flags, length, optional payload, optional DNS query
name). This is the most important decision in the project: it means the
detectors, the correlator and the whole test suite run on plain Python objects
with no capture dependency, and the same detection path serves live traffic,
replayed files and unit tests. The core imports no third-party package.

## Pipeline

```
PacketSource -> Pipeline.process -> [detectors] -> Correlator -> sink
```

`Pipeline` owns the detectors, the flow table and the correlator and nothing
else. It does not know where packets come from or where alerts go; the CLI
wires a source to a sink around it. Adding a detector is dropping a module in
`detect/` and importing it; the registry does the rest.

## Detectors

Detectors split into two families. Signature detection matches compiled regex
rules against payloads (SQLi, XSS, path traversal, command injection).
Behavioral detection watches for shapes that no single packet reveals: a source
touching many ports (scan), a burst of half-open SYNs (SYN flood), many sources
on one victim (distributed flood), repeated openers to auth ports (brute
force), and long high-entropy DNS names (tunneling).

Each behavioral detector keeps per-key sliding windows and is O(1) per packet,
not O(window). The port-scan and DDoS detectors need a distinct count over the
window (distinct ports, distinct sources); they keep a reference count per value
and adjust it on insert and eviction, so the distinct count is always current
without rescanning the buffer. Thresholds are all in `config.py` and overridable
per run, so tuning never touches detector logic.

Detectors are deliberately noisy: each fires on every packet that still matches.
Silencing is not their job.

## Correlation

A single ongoing scan or flood matches on thousands of consecutive packets. The
correlator collapses repeats of the same event inside a cooldown into one,
counts how many raw hits each absorbed, and keeps the category and severity
tallies. In the sample capture this turns 221 raw detections into 4 events.

Event identity is the subtle part. Most alerts are identified by source and
destination, but a flood rotates its source every packet while the victim stays
fixed. Keying the event on the source would explode one flood into one event per
spoofed address. So flood-type detectors set an explicit `event_key` on the
alert built from the victim, and the correlator honours it over the default.
This is covered by a regression test.

## Performance

The engine sustains about 116,000 packets per second on a single CPython 3.14
core through all six detectors and the correlator (`bench/benchmark.py`,
200k-packet synthetic workload, measured separately from pcap parsing so the
number reflects detection, not scapy's decoder). Cost is dominated by the
per-packet dictionary and deque bookkeeping in the behavioral detectors; the
signature detector only runs when a packet carries a payload. The design choice
that pays off here is the flat record type: no object graph is walked per packet.

## Scaling to 100x

A single Python process is the current ceiling, and the GIL means one core does
the detection. The path past that is already implied by the seams:

- Capture and detection are separable. Run lightweight capture agents that only
  normalize packets to the `Packet` record and publish them onto a queue
  (Redis streams or Kafka), with a pool of detection workers consuming it.
- Sharding is natural: route by victim address (or flow hash) so that all
  packets for one host land on the same worker. Every behavioral detector keys
  its state by victim or by flow already, so a shard is self-contained and no
  cross-worker state is needed for the detectors as written.
- The correlator and the stores (events, flow stats) become shared services. At
  that point events go to a durable store (Postgres) rather than a list, and the
  dashboard reads from it.

What would not change: the record type, the detector interface and the detection
logic. That is the point of the seam.

## Threat model

vigil parses input from hostile sources by definition, so the engine treats
every field as untrusted. It never evaluates payloads, only matches regex
against them. Memory is bounded under flood: the live source hands packets
through a fixed-size queue and drops (and counts) the overflow rather than
buffering without limit, and every detector's state is a sliding window, so a
sustained attack cannot grow state unboundedly for a given key. The dashboard
API is where most of the tool's own attack surface lives, so it is authenticated
from the start: every data endpoint requires a signed JWT, the password is never
baked into the source (it comes from the environment or is generated per run),
credential comparison is constant time, request bodies are validated by pydantic
models, and the dashboard is served same-origin so there is no CORS surface.
Per-client rate limiting is the main hardening still to add.

## Hardest bugs

Two were worth the time to understand rather than paper over.

1. A replayed pcap produced zero packets from the CLI while the library read it
   fine in a scratch script. The cause was scapy link-layer registration: when
   only `scapy.utils` is imported, `PcapReader` resolves the file's link type
   before any layer bindings are loaded, sees link type 1 (Ethernet) as unknown,
   and falls back to raw bytes, so `IP in pkt` is always false. The fix was to
   import the layer modules at the top of the capture module, which registers the
   bindings before any read. The lesson was that scapy's decode table is import
   order sensitive.

2. The correlator was emitting hundreds of SYN-flood events for one flood. The
   event key included the source address, which a flood rotates every packet.
   Fixed by giving flood detectors a victim-based `event_key`, with a regression
   test so it stays fixed.

## Limitations

- No stream reassembly. Signatures match within a single packet's payload, so an
  attack split across TCP segments is missed. This is the biggest gap.
- No TLS inspection. Encrypted payloads are opaque; only metadata is used.
- Thresholds are static. They are sensible defaults, not learned baselines, so a
  very large or very quiet network needs tuning.
- IPv6 is captured and detected on, but the signature rules and some heuristics
  are written with IPv4-era assumptions.
- Detection is per-host and per-flow, not whole-network behavioral modelling.

## Roadmap

Done so far: the detection core, the CLI, the dashboard with its authenticated
FastAPI backend (it currently polls; a websocket push is a later refinement),
Docker and docker-compose packaging, and CI running the suite across Python
3.10 to 3.13.

Still to do, in rough order: TCP flow reassembly so signatures see a full stream;
per-client rate limiting on the API; coverage gating in CI; and the distributed
capture-agent and worker split described above. If it were restarted today the
one thing done earlier would be reassembly, because several detector limitations
trace back to working one packet at a time.
