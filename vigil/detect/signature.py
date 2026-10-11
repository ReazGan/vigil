"""Signature detection over packet payloads.

A small, readable rule set that matches known-bad patterns in application-layer
payloads: SQL injection, cross-site scripting, path traversal, command
injection. Rules are compiled once at import. This is intentionally not a Snort
clone; it is a clear example of the signature half of a hybrid engine, sitting
next to the behavioral detectors.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Optional

from ..config import DEFAULT, Thresholds
from ..models import Alert, Packet, Severity
from .base import Detector, register


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: Severity
    pattern: re.Pattern
    ports: Optional[frozenset] = None   # None = any port


def _rule(id, category, severity, regex, ports=None):
    return Rule(
        id=id,
        category=category,
        severity=severity,
        pattern=re.compile(regex, re.IGNORECASE),
        ports=frozenset(ports) if ports else None,
    )


WEB_PORTS = (80, 443, 8080, 8443, 8000)

RULES: list[Rule] = [
    _rule("sqli-union", "SQL Injection", Severity.HIGH, rb"union\s+select", WEB_PORTS),
    _rule("sqli-tautology", "SQL Injection", Severity.HIGH, rb"'\s*or\s*'?1'?\s*=\s*'?1", WEB_PORTS),
    _rule("sqli-comment", "SQL Injection", Severity.MEDIUM, rb"(;|')\s*--", WEB_PORTS),
    _rule("xss-script", "XSS Attack", Severity.MEDIUM, rb"<script[\s>]", WEB_PORTS),
    _rule("xss-onerror", "XSS Attack", Severity.MEDIUM, rb"on(error|load)\s*=", WEB_PORTS),
    _rule("path-traversal", "Path Traversal", Severity.HIGH, rb"(\.\./){2,}", None),
    _rule("cmd-injection", "Command Injection", Severity.HIGH, rb";\s*(cat|wget|curl|nc|bash|sh)\s", None),
]


@register
class SignatureDetector(Detector):
    name = "signature"
    category = "Signature"

    def __init__(self, cfg: Thresholds = DEFAULT, rules: Optional[list[Rule]] = None) -> None:
        super().__init__(cfg)
        self.rules = rules if rules is not None else RULES

    def inspect(self, pkt: Packet) -> Iterable[Alert]:
        # Prefer the reassembled stream (set by the pipeline for TCP) so a
        # signature split across segments is still caught; fall back to the
        # single packet payload for detectors used standalone.
        data = pkt.stream if pkt.stream is not None else pkt.payload
        if not data:
            return
        for rule in self.rules:
            if rule.ports is not None and pkt.dst_port not in rule.ports:
                continue
            if rule.pattern.search(data):
                yield Alert(
                    ts=pkt.ts,
                    detector=self.name,
                    category=rule.category,
                    severity=rule.severity,
                    src_ip=pkt.src_ip,
                    dst_ip=pkt.dst_ip,
                    summary=f"{rule.category} signature '{rule.id}' matched "
                    f"{pkt.src_ip} -> {pkt.dst_ip}:{pkt.dst_port}",
                    evidence={"rule": rule.id, "port": pkt.dst_port},
                )
