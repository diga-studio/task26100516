"""Core data types for MailSentinel SPF path-budget analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

# SPF verdicts
PASS = "pass"
FAIL = "fail"
SOFTFAIL = "softfail"
NEUTRAL = "neutral"
PERMERROR = "permerror"

QUALIFIER_TO_VERDICT = {
    "+": PASS,
    "-": FAIL,
    "~": SOFTFAIL,
    "?": NEUTRAL,
}

# Maximum number of successful references (include/redirect) per evaluation.
# The 11th reference attempt yields permerror with a final count of 11.
MAX_REFERENCES = 10


@dataclass(frozen=True)
class Mechanism:
    """A single SPF mechanism."""

    kind: str  # "ip4" | "include" | "all"
    qualifier: str  # one of "+", "-", "~", "?"
    value: Optional[str] = None  # CIDR for ip4, domain for include


@dataclass(frozen=True)
class Record:
    """A parsed SPF record."""

    mechanisms: List[Mechanism] = field(default_factory=list)
    redirect: Optional[str] = None  # target domain of redirect=, if any


@dataclass(frozen=True)
class Interval:
    """A result interval covering [start, end] IPv4 addresses (inclusive)."""

    start: str  # dotted-quad, e.g. "0.0.0.0"
    end: str  # dotted-quad, e.g. "255.255.255.255"
    verdict: str
    count: int
